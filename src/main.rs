mod config;
mod templates;

#[macro_use]
extern crate log;
use std::env;

use askama_axum::IntoResponse;
use axum::{
    http::{HeaderMap, HeaderValue, Response},
    routing::{get, post},
    Form, Router,
};
use axum_extra::extract::CookieJar;
use jsonwebtoken::{jwk::Jwk, DecodingKey};
use serde::Deserialize;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }
    pretty_env_logger::init();

    info!("Hello, world!");

    let app = Router::new()
        .route("/", get(templates::Index::get))
        .route("/login", get(templates::Login::get))
        .route("/vote", get(templates::Vote::get))
        .route("/vote", post(templates::Vote::post))
        .route("/auth/callback", post(auth))
        .layer(
            tower_http::set_header::SetResponseHeaderLayer::if_not_present(
                axum::http::header::REFERRER_POLICY,
                HeaderValue::from_static("no-referrer-when-downgrade"),
            ),
        );
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
    Ok(())
}

#[derive(Debug, Deserialize)]
struct AuthBody {
    credential: String,
    g_csrf_token: String,
}
async fn auth(
    headers: HeaderMap,
    cookies: CookieJar,
    Form(form): Form<AuthBody>,
) -> impl IntoResponse {
    dbg!(&form);
    dbg!(&headers);

    if !cookies
        .get("g_csrf_token")
        .map_or(false, |c| c.value() == form.g_csrf_token)
    {
        return Err(Response::builder()
            .status(400)
            .body("Invalid CSRF token".to_string())
            .unwrap());
    }

    let _ = get_decodekey().await;

    Ok("hello")
}

#[derive(Debug, Deserialize)]
struct DecodeKeyBody {
    keys: Vec<Jwk>,
}
async fn get_decodekey() -> anyhow::Result<DecodingKey> {
    let v: DecodeKeyBody = reqwest::get("https://www.googleapis.com/oauth2/v3/certs")
        .await?
        .json()
        .await?;

    dbg!(&v);

    Err(anyhow::anyhow!("todo"))
}
