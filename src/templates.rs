use askama::Template;
use askama_axum::IntoResponse;
use axum_extra::extract::Form;
use serde::Deserialize;

#[derive(Template)]
#[template(path = "index.html")]
pub struct Index {}
impl Index {
    pub async fn get() -> impl IntoResponse {
        Self {}
    }
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct Login {}
impl Login {
    pub async fn get() -> impl IntoResponse {
        Self {}
    }
}

#[derive(Template, Default)]
#[template(path = "vote.html")]
pub struct Vote {
    sortable: VoteForm,
}
impl Vote {
    pub async fn get() -> impl IntoResponse {
        Self::default()
    }

    pub async fn post(Form(FormBody { item: items }): Form<FormBody>) -> impl IntoResponse {
        dbg!(&items);

        VoteForm { items }
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
