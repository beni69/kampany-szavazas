use crate::{auth::save_user, AppState, AppStateContainer, Config, User};
use askama::Template;
use askama_axum::IntoResponse;
use axum::{
    extract::{Extension, State},
    http::Method,
    middleware::Next,
    response::Redirect,
};
use axum_extra::extract::Form;
use bincode::Options;
use serde::Deserialize;
use std::{sync::Arc, time::SystemTime};

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
#[template(path = "vote/vbase.html")]
pub struct VoteBase {
    tab: (usize, usize), // (current, len)
    category: String,
    items: Vec<(usize, String)>,
    voted: bool,
}
#[derive(Debug, Deserialize)]
pub struct SortableBody {
    tab: usize,
    #[serde(rename = "item")]
    items: Vec<usize>,
}
#[derive(Debug, Deserialize)]
pub struct TabBody {
    tab: usize,
    #[serde(default)]
    back: bool,
    item: Vec<usize>,
}
// GET: initial req, returns whole page
// PATCH: reorder, returns sortable (VoteForm)
// PUT: next page, returns tab
// POST: submit vote, returns end screen
// DELETE: undo vote
impl VoteBase {
    pub async fn get(
        State(state): AppState,
        Extension(user): Extension<User>,
    ) -> impl IntoResponse {
        Self {
            tab: (0, state.config.categories.len()),
            category: state.config.categories[0].clone(),
            voted: user.voted,
            items: Self::get_items(&state.config, user, 0),
        }
    }

    pub async fn patch(
        State(state): AppState,
        Extension(mut user): Extension<User>,
        Form(SortableBody { items, tab }): Form<SortableBody>,
    ) -> impl IntoResponse {
        Self::save_vote(&state, &mut user, items, tab, false);

        VoteSortable {
            tab: (tab, state.config.categories.len()),
            items: Self::get_items(&state.config, user, tab),
        }
    }

    pub async fn put(
        State(state): AppState,
        Extension(mut user): Extension<User>,
        Form(form): Form<TabBody>,
    ) -> impl IntoResponse {
        dbg!(&form);

        Self::save_vote(&state, &mut user, form.item, form.tab, false);

        let tab = if form.back {
            form.tab.saturating_sub(1)
        } else {
            form.tab + 1
        };
        VoteTab {
            tab: (tab, state.config.categories.len()),
            category: state.config.categories[tab].clone(),
            items: Self::get_items(&state.config, user, tab),
        }
    }

    pub async fn post(
        State(state): AppState,
        Extension(mut user): Extension<User>,
        Form(SortableBody { items, tab }): Form<SortableBody>,
    ) -> impl IntoResponse {
        dbg!(&&items);

        Self::save_vote(&state, &mut user, items, tab, true);

        VoteDone
    }

    pub async fn delete(
        State(state): AppState,
        Extension(mut user): Extension<User>,
    ) -> impl IntoResponse {
        user.voted = false;
        save_user(&state.db, &user).unwrap();

        // "move back" to last tab
        let tab = state.config.categories.len() - 1;
        VoteTab {
            tab: (tab, state.config.categories.len()),
            category: state.config.categories[tab].clone(),
            items: Self::get_items(&state.config, user, tab),
        }
    }

    /// check if user submited or voting closed
    pub async fn vote_middleware(
        State(state): AppState,
        Extension(user): Extension<User>,
        req: axum::extract::Request,
        next: Next,
    ) -> Result<axum::response::Response, Redirect> {
        if let Some(close) = state.config.close {
            let now = SystemTime::now();
            if close < now {
                return Err(Redirect::to("/vote/closed"));
            }
        }

        if user.voted && (req.method() != Method::GET && req.method() != Method::DELETE) {
            return Err(Redirect::to("/vote"));
        }

        Ok(next.run(req).await)
    }

    fn get_items(config: &Config, user: User, tab: usize) -> Vec<(usize, String)> {
        user.order[tab]
            .iter()
            .map(|i| (*i, config.classes[*i].to_owned()))
            .collect()
    }

    fn save_vote(
        state: &Arc<AppStateContainer>,
        user: &mut User,
        items: Vec<usize>,
        tab: usize,
        voted: bool,
    ) {
        dbg!(&items);

        // prevent spoofing
        let mut sorted = items.clone();
        sorted.sort_unstable();
        if sorted == (0..state.config.classes.len()).collect::<Vec<_>>() {
            user.order[tab] = items;
            if voted {
                user.voted = true;
            }
            save_user(&state.db, &user).unwrap();
        } else {
            warn!("vote update rejected: {items:?}");
        }
    }
}

#[derive(Template)]
#[template(path = "vote/tab.html")]
struct VoteTab {
    tab: (usize, usize), // (current, len)
    category: String,
    items: Vec<(usize, String)>,
}

#[derive(Template)]
#[template(path = "vote/sortable.html")]
struct VoteSortable {
    tab: (usize, usize), // (current, len)
    items: Vec<(usize, String)>,
}

#[derive(Template)]
#[template(path = "vote/done.html")]
struct VoteDone;

#[derive(Template)]
#[template(path = "vote/closed.html")]
pub struct VoteClosed {
    voted: bool,
}
impl VoteClosed {
    pub async fn get(
        State(state): AppState,
        Extension(user): Extension<User>,
    ) -> impl IntoResponse {
        if let Some(close) = state.config.close {
            let now = SystemTime::now();
            if close < now {
                return Ok(Self { voted: user.voted });
            }
        }

        Err(Redirect::to("/vote"))
    }
}

#[derive(Template)]
#[template(path = "admin.html")]
pub struct Admin {
    votes: Vec<Vec<Vec<usize>>>,
}
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
            .filter_map(|u| if u.voted { Some(u.order) } else { None });

        let votes = x.collect::<Vec<_>>();

        info!("{votes:?}");

        Self { votes }
    }
}
