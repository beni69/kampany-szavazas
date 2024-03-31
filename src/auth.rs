use crate::{AppState, Config, User};
use askama_axum::IntoResponse;
use axum::{extract::State, http::Response, middleware::Next, response::Redirect, Extension, Form};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use bincode::Options;
use jsonwebtoken::{jwk::JwkSet, DecodingKey, TokenData, Validation};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct AuthBody {
    credential: String,
    g_csrf_token: String,
}
#[derive(Debug, Deserialize)]
struct Claims {
    /// account ID
    sub: String,
    /// domain
    hd: String,
    email: String,
    email_verified: bool,
    picture: String,
    // used for hungarian name ordering
    given_name: String,
    family_name: String,
}
pub(super) async fn auth(
    State(state): AppState,
    cookies: CookieJar,
    Form(form): Form<AuthBody>,
) -> impl IntoResponse {
    let Some(Some(c)) = cookies.get("g_csrf_token").map(|c| {
        if c.value() == form.g_csrf_token {
            Some(c.to_owned())
        } else {
            None
        }
    }) else {
        return Err(Response::builder()
            .status(400)
            .body("Invalid CSRF token".to_string())
            .unwrap());
    };
    let cookies = cookies.remove(c);

    let token = match verify_jwt(&state.config, &form.credential).await {
        Ok(token) => token,
        Err(e) => {
            error!("{}", &e);
            return Err(Response::builder()
                .status(400)
                .body("Invalid token".to_string())
                .unwrap());
        }
    };

    if token.claims.email_verified == false || token.claims.hd != "szlgbp.hu" {
        return Err(Response::builder()
            .status(400)
            .body("Invalid Google account".to_string())
            .unwrap());
    }

    let is_admin = state.config.admins.contains(&token.claims.email);

    let user: User = match state.db.get(&token.claims.sub) {
        Ok(Some(bin)) => {
            let mut user: User = bincode::DefaultOptions::new().deserialize(&bin).unwrap();
            info!("user found: {user:?}");

            // react to .env ADMINS changes
            if is_admin != user.admin {
                warn!(
                    "{} admin status changed: {}",
                    &token.claims.email, &is_admin
                );
                user.admin = is_admin;
                save_user(&state.db, &user).unwrap();
            }

            user
        }
        _ => {
            let user = User {
                id: token.claims.sub.clone(),
                email: token.claims.email,
                name: format!("{} {}", token.claims.family_name, token.claims.given_name),
                pfp: token.claims.picture,
                order: (0..state.config.classes.len()).collect(),
                voted: false,
                tokens: Vec::new(),
                admin: is_admin,
            };
            save_user(&state.db, &user).unwrap();
            user
        }
    };

    let (_user, token) = new_token(&state.db, user).unwrap();

    Ok((
        cookies.add(Cookie::build(("token", token.to_string())).path("/")),
        Redirect::to("/vote"),
    ))
}

async fn verify_jwt(config: &Config, jwt: &str) -> anyhow::Result<TokenData<Claims>> {
    let jwt_header = jsonwebtoken::decode_header(jwt)?;

    let key = get_decodekey(
        &jwt_header
            .kid
            .ok_or_else(|| anyhow::anyhow!("kid not present in header"))?,
    )
    .await?;

    let mut validation = Validation::new(jwt_header.alg);
    validation.set_audience(&[&config.google_client_id]);
    validation.set_issuer(&["https://accounts.google.com"]);
    validation.set_required_spec_claims(&["exp", "nbf", "aud", "iss", "sub"]);

    let token = jsonwebtoken::decode::<Claims>(&jwt, &key, &validation)?;
    Ok(token)
}

// WARN: every login request will "block" on this google endpoint
// proper solution would be to cache the keys, but it should be fine
async fn get_decodekey(kid: &str) -> anyhow::Result<DecodingKey> {
    let keys: JwkSet = reqwest::get("https://www.googleapis.com/oauth2/v3/certs")
        .await?
        .json()
        .await?;

    let k = keys
        .find(kid)
        .ok_or_else(|| anyhow::anyhow!("kid not found"))?;
    Ok(DecodingKey::from_jwk(k)?)
}

pub(super) async fn logout(
    Extension(mut user): Extension<User>,
    Extension(token): Extension<Token>,
    cookies: CookieJar,
    State(state): AppState,
) -> impl IntoResponse {
    let token = token.unwrap();

    state
        .db
        .open_tree("tokens")
        .unwrap()
        .remove(token.to_be_bytes())
        .unwrap();

    user.tokens
        .remove(user.tokens.iter().position(|t| *t == token).unwrap());
    save_user(&state.db, &user).unwrap();

    (cookies.remove("token"), [("HX-Refresh", "true")])
}

pub(super) async fn clear_tokens(
    Extension(mut user): Extension<User>,
    cookies: CookieJar,
    State(state): AppState,
) -> impl IntoResponse {
    let tree = state.db.open_tree("tokens").unwrap();
    for token in &user.tokens {
        tree.remove(&token.to_be_bytes()).unwrap();
    }
    user.tokens.clear();
    save_user(&state.db, &user).unwrap();

    (cookies.remove("token"), Redirect::to("/"))
}

fn new_token(db: &sled::Db, mut user: User) -> anyhow::Result<(User, String)> {
    let tree = db.open_tree("tokens")?;
    let token = {
        let mut buf = [0; std::mem::size_of::<u64>()];
        SystemRandom::new().fill(&mut buf)?;
        u64::from_ne_bytes(buf)
    };
    tree.insert(&token.to_be_bytes(), &user.id[..])?;
    user.tokens.push(token);
    save_user(db, &user)?;

    let hex = format!("{token:x}");
    Ok((user, hex))
}
fn get_user(db: &sled::Db, token: &str) -> anyhow::Result<(User, u64)> {
    let tree = db.open_tree("tokens")?;
    let key = u64::from_str_radix(token, 16)?;
    let Some(bin) = tree.get(key.to_be_bytes())? else {
        anyhow::bail!("user not found")
    };
    let uid = String::from_utf8(bin.to_vec())?;

    let Some(bin) = db.get(&uid)? else {
        anyhow::bail!("user not found")
    };
    let user = bincode::DefaultOptions::new().deserialize(&bin).unwrap();
    Ok((user, key))
}
pub(super) fn save_user(db: &sled::Db, user: &User) -> anyhow::Result<()> {
    let bin = bincode::DefaultOptions::new().serialize(&user)?;
    db.insert(&user.id, bin)?;
    Ok(())
}

type Token = Option<u64>;
pub(super) async fn middleware(
    State(state): AppState,
    cookies: CookieJar,
    mut req: axum::extract::Request,
    next: Next,
) -> axum::response::Response {
    let token = cookies.get("token");

    let (user, token): (_, Token) = match token.map(|c| get_user(&state.db, &c.value())) {
        Some(Ok((user, token))) => (Some(user), Some(token)),
        _ => (None, None),
    };
    req.extensions_mut().insert(user);
    req.extensions_mut().insert(token);

    next.run(req).await
}

pub(super) async fn required(
    Extension(user): Extension<Option<User>>,
    mut req: axum::extract::Request,
    next: Next,
) -> Result<axum::response::Response, Redirect> {
    let Some(user) = user else {
        return Err(Redirect::to("/login"));
    };

    req.extensions_mut().insert(user);
    Ok(next.run(req).await)
}

pub(super) async fn required_admin(
    Extension(user): Extension<User>,
    req: axum::extract::Request,
    next: Next,
) -> Result<axum::response::Response, Redirect> {
    if !user.admin {
        return Err(Redirect::to("/"));
    };
    Ok(next.run(req).await)
}
