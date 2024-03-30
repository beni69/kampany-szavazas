mod auth;
mod config;
mod templates;

#[macro_use]
extern crate log;
use axum::{
    extract::State,
    middleware::{from_fn, from_fn_with_state},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::{env, sync::Arc};
use tower_http::services::ServeDir;

// DB default tree: User::id => User
// DB tokens tree: token => User::id
#[derive(Debug, Clone, Serialize, Deserialize)]
struct User {
    id: String,
    email: String,
    name: String,
    pfp: String,
    order: Vec<u8>,
    voted: bool,
    tokens: Vec<u64>,
    admin: bool,
}

struct AppStateContainer {
    db: sled::Db,
}
type AppState = State<Arc<AppStateContainer>>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }
    pretty_env_logger::init();

    info!("Hello, world!");

    let db: sled::Db = sled::open("db").unwrap();

    let state = Arc::new(AppStateContainer { db });

    let auth_router = Router::new()
        .route("/me", get(templates::Me::get))
        .route("/me/clear", get(auth::clear_tokens))
        .route("/logout", get(auth::logout))
        .route("/vote", get(templates::Vote::get))
        .route("/vote", post(templates::Vote::post))
        .layer(from_fn(auth::required));

    let app = Router::new()
        .route("/", get(templates::Index::get))
        .route("/login", get(templates::Login::get))
        .route("/auth/callback", post(auth::auth))
        .merge(auth_router)
        // .layer(
        //     tower_http::set_header::SetResponseHeaderLayer::if_not_present(
        //         axum::http::header::REFERRER_POLICY,
        //         HeaderValue::from_static("no-referrer-when-downgrade"),
        //     ),
        // )
        .layer(from_fn_with_state(state.clone(), auth::middleware))
        .with_state(state);

    let router = Router::new()
        .nest_service("/static", ServeDir::new("static"))
        .merge(app);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, router).await.unwrap();
    Ok(())
}
