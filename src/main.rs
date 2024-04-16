mod auth;
mod templates;

#[macro_use]
extern crate log;
use axum::{
    extract::State,
    middleware::{from_fn, from_fn_with_state},
    routing::{get, post},
    Router,
};
use recap::Recap;
use serde::{Deserialize, Serialize};
use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::SystemTime,
};
use tower_http::services::ServeDir;

#[derive(Debug, Deserialize)]
struct Config {
    #[serde(default = "def_host")]
    host: IpAddr,
    #[serde(default = "def_port")]
    port: u16,
    #[serde(default = "def_gid")]
    google_client_id: String,
    #[serde(default = "def_db")]
    db_path: String,
    #[serde(default = "def_classes")]
    classes: Vec<String>,
    #[serde(default)]
    admins: Vec<String>,
    #[serde(default = "def_cat")]
    categories: Vec<String>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    close: Option<SystemTime>,
}
fn def_host() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
}
fn def_port() -> u16 {
    3000
}
fn def_gid() -> String {
    "195594341058-l1e4lkla1giucgbhggfmreumha6qdgmq.apps.googleusercontent.com".to_string()
}
fn def_db() -> String {
    "./db".to_string()
}
fn def_classes() -> Vec<String> {
    ('A'..='F').map(|f| format!("{f} osztály")).collect()
}
fn def_cat() -> Vec<String> {
    [
        "Legjobb dizájn",
        "Legjobb tánc",
        "Legjobb programok",
        "Fődíj",
    ]
    .map(Into::into)
    .into()
}

#[derive(Debug, Deserialize, PartialEq, Recap)]
#[recap(
    regex = r#"(?P<fname>.+?)(?:\.(?P<lname>.+?))??(?:\.(?P<year>[0-9]{2})(?P<class>[a-g]))?@szlgbp\.hu"#
)]
struct SchoolEmail {
    fname: String,
    lname: Option<String>,
    year: Option<u8>,
    class: Option<char>,
}

// DB default tree: User::id => User
// DB tokens tree: token => User::id
// DB points tree: class => Vec<Points>
#[derive(Debug, Clone, Serialize, Deserialize)]
struct User {
    id: String,
    email: String,
    name: String,
    pfp: String,
    order: Vec<Vec<usize>>,
    voted: bool,
    tokens: Vec<u64>,
    admin: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct Points {
    class: usize,
    reason: String,
    points: i32,
}

struct AppStateContainer {
    config: Config,
    db: sled::Db,
}
type AppState = State<Arc<AppStateContainer>>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let envfile = dotenvy::dotenv();
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "kampany_szavazas=debug");
    }
    env_logger::init();
    if let Ok(f) = envfile {
        info!("Config loaded from {f:?}");
    }

    let config = envy::from_env::<Config>()?;

    let db: sled::Db = sled::open(&config.db_path).unwrap();

    let state = Arc::new(AppStateContainer { config, db });

    let admin_router = Router::new()
        .route("/", get(templates::Admin::get))
        .route(
            "/points",
            get(templates::AdminPoints::get)
                .post(templates::AdminPoints::post)
                .delete(templates::AdminPoints::delete),
        )
        .route("/results", get(templates::AdminResults::get))
        .route_layer(from_fn(auth::required_admin));

    let auth_router = Router::new()
        .route("/me", get(templates::Me::get))
        .route("/me/clear", get(auth::clear_tokens))
        .route("/auth/logout", get(auth::logout).post(auth::logout))
        .nest(
            "/vote",
            Router::new()
                .route(
                    "/",
                    get(templates::VoteBase::get)
                        .patch(templates::VoteBase::patch)
                        .put(templates::VoteBase::put)
                        .post(templates::VoteBase::post)
                        .delete(templates::VoteBase::delete),
                )
                .route_layer(from_fn_with_state(
                    state.clone(),
                    templates::VoteBase::vote_middleware,
                ))
                .route("/closed", get(templates::VoteClosed::get))
                .route("/prohibited", get(templates::VoteProhibited::get)),
        )
        .nest("/admin", admin_router)
        .route_layer(from_fn(auth::required));

    let app = Router::new()
        .route("/", get(templates::Index::get))
        .route("/login", get(templates::Login::get))
        .route("/auth/callback", post(auth::auth))
        .merge(auth_router)
        .layer(from_fn_with_state(state.clone(), auth::middleware))
        .with_state(state.clone());

    let router = Router::new()
        .nest_service("/static", ServeDir::new("static"))
        .merge(app);

    let addr: SocketAddr = (state.config.host, state.config.port).into();
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    info!("Listening on {addr}");
    axum::serve(listener, router).await.unwrap();
    Ok(())
}

#[cfg(test)]
mod email_regex {
    use super::SchoolEmail;

    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }

    #[test]
    fn student() {
        let email: SchoolEmail = "gec.imre.20f@szlgbp.hu".parse().unwrap();
        let res = SchoolEmail {
            fname: "gec".into(),
            lname: Some("imre".into()),
            year: Some(20),
            class: Some('f'),
        };

        assert_eq!(email, res);
    }

    #[test]
    fn test_student() {
        let email: SchoolEmail = "szt0.gp00.20g@szlgbp.hu".parse().unwrap();
        let res = SchoolEmail {
            fname: "szt0".into(),
            lname: Some("gp00".into()),
            year: Some(20),
            class: Some('g'),
        };

        assert_eq!(email, res);
    }

    #[test]
    fn teacher() {
        let email: SchoolEmail = "vegh.bela@szlgbp.hu".parse().unwrap();
        let res = SchoolEmail {
            fname: "vegh".into(),
            lname: Some("bela".into()),
            year: None,
            class: None,
        };

        assert_eq!(email, res);
    }

    #[test]
    fn single_name() {
        let email: SchoolEmail = "moriczka@szlgbp.hu".parse().unwrap();
        let res = SchoolEmail {
            fname: "moriczka".into(),
            lname: None,
            year: None,
            class: None,
        };

        assert_eq!(email, res);
    }

    #[test]
    fn single_name_year() {
        let email: SchoolEmail = "gezuka.19a@szlgbp.hu".parse().unwrap();
        let res = SchoolEmail {
            fname: "gezuka".into(),
            lname: None,
            year: Some(19),
            class: Some('a'),
        };

        assert_eq!(email, res);
    }
}
