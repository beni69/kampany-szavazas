use crate::{auth::save_user, AppState, AppStateContainer, Config, Points, User};
use askama::Template;
use askama_axum::IntoResponse;
use axum::{
    extract::{Extension, Query, State},
    http::Method,
    middleware::Next,
    response::Redirect,
};
use axum_extra::extract::Form;
use bincode::Options;
use chrono::Datelike;
use itertools::Itertools;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use std::{
    sync::Arc,
    time::{Instant, SystemTime},
};

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
            save_user(&state.db, user).unwrap();
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
                false
            }
            Err(e) => {
                error!("{e}");
                // couldn't parse email => can't vote (will have to report bug)
                true
            }
        }
    }

    pub async fn get(Extension(user): Extension<User>) -> impl IntoResponse {
        if Self::participating(&user.email) {
            Ok(Self)
        } else {
            Err(Redirect::to("/vote"))
        }
    }
}

#[derive(Template)]
#[template(path = "admin/admin.html")]
pub struct Admin;
impl Admin {
    pub async fn get() -> impl IntoResponse {
        Self
    }
}

#[derive(Template)]
#[template(path = "admin/points.html")]
pub struct AdminPoints {
    classes: Vec<String>,
    points: Vec<Vec<(u16, Points)>>,
}
#[derive(Debug, Deserialize)]
pub struct AdminiPointsDelete {
    id: u16,
}
impl AdminPoints {
    pub fn list_points(db: &sled::Db, config: &Config) -> anyhow::Result<Vec<Vec<(u16, Points)>>> {
        let mut points = Vec::new();
        for _ in 0..config.classes.len() {
            points.push(Vec::new());
        }

        let tree = db.open_tree("points")?;
        for p in tree.iter().filter_map(|x| x.ok()).flat_map(|(id, bin)| {
            bincode::DefaultOptions::new()
                .deserialize::<Points>(&bin)
                .map(|bin| {
                    // kill me
                    (
                        u16::from_be_bytes(
                            id.split_at(std::mem::size_of::<u16>())
                                .0
                                .try_into()
                                .unwrap(),
                        ),
                        bin,
                    )
                })
        }) {
            points[p.1.class].push(p);
        }

        Ok(points)
    }

    fn add_points(db: &sled::Db, points: Points) -> anyhow::Result<()> {
        let tree = db.open_tree("points")?;
        let bin = bincode::DefaultOptions::new().serialize(&points)?;
        let id = {
            let mut buf = [0; std::mem::size_of::<u16>()];
            loop {
                SystemRandom::new().fill(&mut buf)?;
                if !tree.contains_key(buf)? {
                    break;
                }
            }
            buf
        };
        tree.insert(id, bin)?;
        Ok(())
    }

    fn delete_points(db: &sled::Db, id: u16) -> anyhow::Result<()> {
        let tree = db.open_tree("points")?;
        tree.remove(id.to_be_bytes())?;
        Ok(())
    }

    pub async fn get(State(state): AppState) -> impl IntoResponse {
        Self {
            points: Self::list_points(&state.db, &state.config).unwrap(),
            classes: state.config.classes.clone(),
        }
    }

    pub async fn post(State(state): AppState, Form(points): Form<Points>) -> impl IntoResponse {
        Self::add_points(&state.db, points).unwrap();
        Self {
            points: Self::list_points(&state.db, &state.config).unwrap(),
            classes: state.config.classes.clone(),
        }
    }

    pub async fn delete(
        State(state): AppState,
        Query(form): Query<AdminiPointsDelete>,
    ) -> impl IntoResponse {
        Self::delete_points(&state.db, form.id).unwrap();
        Self {
            points: Self::list_points(&state.db, &state.config).unwrap(),
            classes: state.config.classes.clone(),
        }
    }
}

#[derive(Template)]
#[template(path = "admin/results.html")]
pub struct AdminResults {
    categories: Vec<String>,
    votes: Vec<Vec<Vec<usize>>>,
    results: Vec<Vec<(String, f64)>>,
    user_count: usize,
    points_len: usize,
    points_acc: i32,
}
impl AdminResults {
    pub async fn get(
        State(state): AppState,
        // Extension(mut user): Extension<User>,
    ) -> impl IntoResponse {
        let started = Instant::now();

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
        // generate arrays to hold results
        let mut scores: Vec<Vec<i32>> = std::iter::repeat(
            std::iter::repeat(0)
                .take(state.config.classes.len())
                .collect(),
        )
        .take(state.config.categories.len())
        .collect();

        // fill `scores` with the results
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

        // process score penalties
        let mut points_len = 0;
        let mut points_acc = 0;
        if let Some(last) = scores.last_mut() {
            let points = AdminPoints::list_points(&state.db, &state.config)
                .unwrap()
                .into_iter()
                .map(|class_points| {
                    class_points
                        .into_iter()
                        .map(|(_, points)| {
                            points_len += 1;
                            points.points
                        })
                        .sum::<i32>()
                });
            for (i, amount) in points.enumerate() {
                points_acc += amount;
                last[i] -= amount * 3;
            }
        }

        // combine points with classnames and apply a descending sort
        // [category][place] = class
        let results: Vec<Vec<(String, f64)>> = scores
            .iter()
            .map(|cat| {
                cat.iter()
                    .zip(state.config.classes.iter())
                    .sorted_by(|a, b| Ord::cmp(a.0, b.0).reverse())
                    .map(|(score, class)| (class.to_owned(), *score as f64))
                    .collect()
            })
            .collect();

        let time = started.elapsed();
        info!(
            "Processed {} votes - {} penalties in {}μs",
            votes.len(),
            points_len,
            time.as_micros()
        );

        Self {
            user_count,
            points_len,
            points_acc,
            categories: state.config.categories.clone(),
            votes,
            results,
        }
    }
}
