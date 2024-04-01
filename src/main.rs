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
use serde::{Deserialize, Serialize};
use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
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
    ('A'..='F').map(|c| format!("{c} osztály")).collect()
}
fn def_cat() -> Vec<String> {
    vec!["Fődíj".to_string()]
}

// DB default tree: User::id => User
// DB tokens tree: token => User::id
#[derive(Debug, Clone, Serialize, Deserialize)]
struct User {
    id: String,
    email: String,
    name: String,
    pfp: String,
    order: Vec<usize>, // TODO: Vec<Vec<usize>>
    voted: bool,
    tokens: Vec<u64>,
    admin: bool,
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
        env::set_var("RUST_LOG", "info");
    }
    pretty_env_logger::init();
    if let Ok(f) = envfile {
        info!("Config loaded from {f:?}");
    }

    let config = envy::from_env::<Config>()?;

    let db: sled::Db = sled::open(&config.db_path).unwrap();

    let state = Arc::new(AppStateContainer { config, db });

    let admin_router = Router::new()
        .route("/", get(templates::Admin::get))
        .route_layer(from_fn(auth::required_admin));

    // TODO: /vote/closed, CLOSED env var
    let auth_router = Router::new()
        .route("/me", get(templates::Me::get))
        .route("/me/clear", get(auth::clear_tokens))
        .route("/auth/logout", get(auth::logout).post(auth::logout))
        .nest(
            "/vote",
            Router::new().route(
                "/",
                get(templates::VoteBase::get)
                    .patch(templates::VoteBase::patch)
                    .put(templates::VoteBase::put)
                    .post(templates::VoteBase::post)
                    .delete(templates::VoteBase::delete),
            ),
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
