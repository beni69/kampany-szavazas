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
use chrono::Datelike;
use itertools::Itertools;
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
    // TODO: exclude users from participating classes
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

        // filter out participating students
        if VoteProhibited::participating(&user.email) {
            return Err(Redirect::to("/vote/prohibited"));
        }

        // reject vote changing methods from users who voted
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
#[template(path = "vote/prohibited.html")]
pub struct VoteProhibited;
impl VoteProhibited {
    pub fn participating(email_str: &str) -> bool {
        match email_str.parse::<crate::SchoolEmail>() {
            Ok(email) => {
                // teacher => can always vote
                let Some(year) = email.year else {
                    return false;
                };

                // participating in event => can't vote
                let current_year = chrono::Utc::now().year();
                if (year as i32) + 2000 + 3 == current_year {
                    return true;
                }

                // (presumably) other student => can vote
                return false;
            }
            Err(e) => {
                error!("{e}");
                // couldn't parse email => can't vote (will have to report bug)
                return true;
            }
        }
    }

    pub async fn get(
        State(state): AppState,
        Extension(user): Extension<User>,
    ) -> impl IntoResponse {
        if Self::participating(&user.email) {
            Ok(Self)
        } else {
            Err(Redirect::to("/vote"))
        }
    }
}

#[derive(Template)]
#[template(path = "admin.html")]
pub struct Admin {
    categories: Vec<String>,
    votes: Vec<Vec<Vec<usize>>>,
    results: Vec<Vec<(String, f64)>>,
    user_count: usize,
}
impl Admin {
    pub async fn get(
        State(state): AppState,
        // Extension(mut user): Extension<User>,
    ) -> impl IntoResponse {
        let mut user_count = 0usize;

        let x = state
            .db
            .iter()
            .map(|x| {
                user_count += 1;
                x
            })
            .filter_map(|x| x.ok())
            .flat_map(|(_, bin)| bincode::DefaultOptions::new().deserialize::<User>(&bin))
            .filter_map(|u| if u.voted { Some(u.order) } else { None }); // only count submitted votes

        // [user][category][place] = class
        let votes = x.collect::<Vec<_>>();

        // [category][class] = score
        let mut scores: Vec<Vec<i32>> = std::iter::repeat(
            std::iter::repeat(0)
                .take(state.config.classes.len())
                .collect(),
        )
        .take(state.config.categories.len())
        .collect();

        // for each user
        for vote in votes.iter() {
            // take each category
            for (category, order) in vote.iter().enumerate() {
                // take the order of the top 3
                for (class, score) in order.iter().take(3).zip((1..=3).rev()) {
                    scores[category][*class] += score;
                }
            }
        }

        // TODO: process score penalties??

        // [category][place] = class
        let results: Vec<Vec<(String, f64)>> = scores
            .iter()
            .map(|cat| {
                cat.iter()
                    .zip(state.config.classes.iter())
                    .sorted_by(|a, b| Ord::cmp(a.0, b.0))
                    .rev()
                    .map(|(score, class)| (class.to_owned(), *score as f64))
                    .collect()
            })
            .collect();

        Self {
            user_count,
            categories: state.config.categories.clone(),
            votes,
            results,
        }
    }
}

fn transpose2<T>(v: Vec<Vec<T>>) -> Vec<Vec<T>> {
    assert!(!v.is_empty());
    let len = v[0].len();
    let mut iters: Vec<_> = v.into_iter().map(|n| n.into_iter()).collect();
    (0..len)
        .map(|_| {
            iters
                .iter_mut()
                .map(|n| n.next().unwrap())
                .collect::<Vec<T>>()
        })
        .collect()
}
