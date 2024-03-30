use askama::Template;
use askama_axum::IntoResponse;
use axum::{
    extract::{Extension, State},
    response::Redirect,
};
use axum_extra::extract::Form;
use serde::Deserialize;

use crate::{AppState, User};

#[derive(Template)]
#[template(path = "index.html")]
pub struct Index {
    logged_in: bool,
}
impl Index {
    pub async fn get(Extension(user): Extension<Option<User>>) -> impl IntoResponse {
        Self {
            logged_in: user.is_some(),
        }
    }
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct Login {}
impl Login {
    pub async fn get(Extension(user): Extension<Option<User>>) -> impl IntoResponse {
        if user.is_some() {
            return Err(Redirect::to("/me"));
        }
        Ok(Self {})
    }
}

#[derive(Template)]
#[template(path = "me.html")]
pub struct Me {
    user: User,
    json: String,
}
impl Me {
    pub async fn get(Extension(user): Extension<User>) -> impl IntoResponse {
        let json = serde_json::to_string_pretty(&user).unwrap();
        Self { user, json }
    }
}

#[derive(Template, Default)]
#[template(path = "vote.html")]
pub struct Vote {
    sortable: VoteForm,
}
impl Vote {
    pub async fn get(Extension(user): Extension<User>) -> impl IntoResponse {
        Self {
            sortable: VoteForm { items: user.order },
        }
    }

    pub async fn post(
        State(state): AppState,
        Extension(mut user): Extension<User>,
        Form(FormBody { item: items }): Form<FormBody>,
    ) -> impl IntoResponse {
        dbg!(&items);

        user.order = items;
        crate::auth::save_user(&state.db, &user).unwrap();

        VoteForm { items: user.order }
    }
}
#[derive(Debug, Deserialize)]
pub struct FormBody {
    item: Vec<u8>,
}

#[derive(Template)]
#[template(path = "sortable.html")]
struct VoteForm {
    items: Vec<u8>,
}
impl Default for VoteForm {
    fn default() -> Self {
        Self {
            items: vec![1, 2, 3, 4, 5],
        }
    }
}
