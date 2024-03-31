use crate::{auth::save_user, AppState, Config, User};
use askama::Template;
use askama_axum::IntoResponse;
use axum::{
    extract::{Extension, State},
    response::Redirect,
};
use axum_extra::{extract::Form, response::Html};
use bincode::Options;
use serde::Deserialize;

#[derive(Template)]
#[template(path = "index.html")]
pub struct Index {
    maybe_user: Option<User>,
}
impl Index {
    pub async fn get(Extension(maybe_user): Extension<Option<User>>) -> impl IntoResponse {
        Self { maybe_user }
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

#[derive(Template)]
#[template(path = "vote.html")]
pub struct Vote {
    sortable: VoteForm,
}
#[derive(Debug, Deserialize)]
pub struct FormBody {
    item: Vec<usize>,
}
impl Vote {
    pub async fn get(
        State(state): AppState,
        Extension(user): Extension<User>,
    ) -> impl IntoResponse {
        Self {
            sortable: VoteForm::new(&state.config, user.order),
        }
    }

    pub async fn post(
        State(state): AppState,
        Extension(mut user): Extension<User>,
        Form(FormBody { item: items }): Form<FormBody>,
    ) -> impl IntoResponse {
        dbg!(&items);

        // prevent spoofing
        let mut sorted = items.clone();
        sorted.sort_unstable();
        if sorted == (0..state.config.classes.len()).collect::<Vec<_>>() {
            user.order = items;
            save_user(&state.db, &user).unwrap();
        } else {
            warn!("vote update rejected: {items:?}");
        }

        VoteForm::new(&state.config, user.order)
    }

    pub async fn submit(
        State(state): AppState,
        Extension(mut user): Extension<User>,
        Form(FormBody { item: items }): Form<FormBody>,
    ) -> impl IntoResponse {
        dbg!(&&items);

        user.order = items;
        user.voted = true;
        save_user(&state.db, &user).unwrap();

        Html(
            r#"<p class="text-center text-xl">Szavazat leadva!</p>
            <script>window.confetti()</script>"#,
        )
    }
}

#[derive(Template)]
#[template(path = "sortable.html")]
struct VoteForm {
    items: Vec<(usize, String)>,
}
impl VoteForm {
    pub fn new(config: &Config, order: Vec<usize>) -> Self {
        let items = order
            .into_iter()
            .map(|i| (i, config.classes[i].to_owned()))
            .collect();
        Self { items }
    }
}

#[derive(Template)]
#[template(path = "admin.html")]
pub struct Admin {}
impl Admin {
    pub async fn get(
        State(state): AppState,
        // Extension(mut user): Extension<User>,
    ) -> impl IntoResponse {
        let x = state
            .db
            .iter()
            .filter_map(|x| x.ok())
            .flat_map(|(_, bin)| bincode::DefaultOptions::new().deserialize::<User>(&bin))
            .filter_map(|u| u.voted);
        // TODO: get votes

        let x = x.collect::<Vec<_>>();

        Self {}
    }
}
