use std::sync::Arc;
use axum::{
    Extension, 
    Json, 
    Router,
    http::StatusCode,
    response::IntoResponse,
    routing::post
};
use chrono::Local;
use fern::Dispatch;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use sqlx::{
    PgPool, 
    postgres::PgPoolOptions
};

#[derive(Serialize, Deserialize)]
pub struct OPKPayload {
    id: i32,
    key: String,
}

#[derive(Serialize, Deserialize)]
pub struct CreatePayload {
    account: String,
    ik_public: String,
    spk_public: String,
    spk_signature: String,
    opk: Vec<OPKPayload>,
}

#[derive(Deserialize)]
struct NormalPayload { target: String, } 

#[derive(Deserialize)]
struct SearchPayload { account:String, target: String, } 

#[derive(Serialize)]
struct User { 
    account: String, 
    ik_public: String,
    spk_public: String,
    spk_signature: String,
    opk: String,
    id: i32
}

fn setup_logger() -> Result<(), fern::InitError> {
    Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                Local::now().format("[%Y-%m-%d %H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(log::LevelFilter::Info)
        .chain(std::io::stdout())
        .apply()?;
    Ok(())
}

#[tokio::main]
pub async fn start() -> Result<(), Box<dyn std::error::Error>> {
    setup_logger().expect("Failed to initialize logger");
    
    let db = Arc::new(PgPoolOptions::new()
        .max_connections(5)
        .connect(&std::env::var("DATABASE_URL")?)
        .await?);

    let app = Router::new()
        .route("/search/", post(search))
        .route("/create/", post(create))
        .route("/session/", post(session))
        .route("/create/session/", post(create_session))
        .route("/list/session/", post(get_session_list))
        .route("/get/session/", post(get_session))
        .layer(Extension(db.clone()));

    let listener = tokio::net::TcpListener::bind(std::env::var("SERVER_URL")?).await.unwrap();
    info!("Server is running on {}", std::env::var("SERVER_URL")?);
    axum::serve(listener, app).await.unwrap();
    
    Ok(())
}

#[axum::debug_handler]
async fn create(
    Extension(db): Extension<Arc<PgPool>>, 
    Json(payload): Json<CreatePayload>
) -> impl IntoResponse {
    let result = sqlx::query!("SELECT * FROM \"user\" WHERE account = $1", &payload.account)
        .fetch_optional(db.as_ref())
        .await.unwrap();
    
    if result.is_some() {
        sqlx::query!("UPDATE \"user\" SET ik_public = $1, spk_public = $2, spk_signature = $3 WHERE account = $4", 
            &payload.ik_public, &payload.spk_public, &payload.spk_signature, &payload.account
        ).execute(db.as_ref()).await.unwrap();
        sqlx::query!("DELETE FROM opk WHERE account = $1", &payload.account).execute(db.as_ref()).await.unwrap();
        for key in payload.opk.iter() {
            sqlx::query!(
                "INSERT INTO opk (account, opk, id) VALUES ($1, $2, $3)",
                &payload.account, key.key, key.id
            ).execute(db.as_ref()).await.unwrap();
        }
        info!("[Signup] <{}> already exists, updated the account", payload.account);
    } else {
        sqlx::query!(
            "INSERT INTO \"user\" (account, ik_public, spk_public, spk_signature) VALUES ($1, $2, $3, $4)",
            &payload.account, &payload.ik_public, &payload.spk_public, &payload.spk_signature
        ).execute(db.as_ref()).await.unwrap();
        for key in payload.opk.iter() {
            sqlx::query!(
                "INSERT INTO opk (account, opk, id) VALUES ($1, $2, $3)",
                &payload.account, key.key, key.id
            ).execute(db.as_ref()).await.unwrap();
        }
        info!("[Signup] <{}> created an account", payload.account);
    }
    
    StatusCode::OK
}


#[axum::debug_handler]
async fn search(
    Extension(db): Extension<Arc<PgPool>>, 
    Json(payload): Json<SearchPayload>
) -> impl IntoResponse {
    info!("[Search] {} is searching for {}", payload.account, payload.target);
    let result = sqlx::query!("SELECT account FROM \"user\" WHERE account like $1 and account != $2", format!("%{}%", payload.target), payload.account)
        .fetch_all(db.as_ref())
        .await.unwrap();
    
    let mut users = vec![];
    for row in result {
        users.push(row.account);
    }
    Json(users)
}

#[axum::debug_handler]
async fn session(
    Extension(db): Extension<Arc<PgPool>>,
    Json(payload): Json<NormalPayload>
) -> impl IntoResponse {
    info!("[Session] Creating session for {}", payload.target);
    let result = sqlx::query!("SELECT * FROM \"user\" WHERE account = $1", &payload.target)
        .fetch_optional(db.as_ref())
        .await.unwrap();
    
    if let Some(row) = result {
        let result = sqlx::query!("SELECT * FROM opk WHERE account = $1 ORDER BY RANDOM() LIMIT 1;", &payload.target)
            .fetch_optional(db.as_ref())
            .await.unwrap();
        
        if let Some(opk) = result {
            let user = User {
                account: row.account,
                ik_public: row.ik_public,
                spk_public: row.spk_public,
                spk_signature: row.spk_signature,
                opk: opk.opk,
                id: opk.id
            };
            info!("[Session] <{}> created a session", payload.target);
            (StatusCode::OK, Json(Some(user)))
        } else {
            warn!("[Session] <{}> does not have any one-time prekeys", payload.target);
            (StatusCode::NOT_FOUND, Json(None::<User>))
        }
    } else {
        warn!("[Session] <{}> does not exist", payload.target);
        (StatusCode::NOT_FOUND, Json(None::<User>))
    } 
}

#[derive(Serialize, Deserialize)]
struct RequestPayload {
    account: String,
    target: String,
    ikp: String,
    ekp: String,
    opk_id: i32,
}

#[axum::debug_handler]
async fn create_session(
    Extension(db): Extension<Arc<PgPool>>,
    Json(payload): Json<RequestPayload>
) -> impl IntoResponse {
    info!("[Session] {} Creating session for {}", payload.account, payload.target);
    
    let temp = sqlx::query!(
        "INSERT INTO request (account, target, ek, ikp, id) VALUES ($1, $2, $3, $4, $5)",
        &payload.account, &payload.target, &payload.ekp, &payload.ikp, payload.opk_id
    ).execute(db.as_ref()).await;
    
    if temp.is_ok() {
        info!("[Session] <{}> requested a session with <{}>", payload.account, payload.target);
        StatusCode::OK
    } else {
        warn!("[Session] <{}> failed to request a session with <{}>", payload.account, payload.target);
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

#[axum::debug_handler]
async fn get_session_list(
    Extension(db): Extension<Arc<PgPool>>,
    Json(payload): Json<NormalPayload>
) -> impl IntoResponse {
    let result = sqlx::query!("SELECT account FROM request WHERE target = $1",&payload.target)
        .fetch_all(db.as_ref())
        .await.unwrap();
    
    let mut users = vec![];
    for row in result {
        users.push(row.account);
    }
    
    info!("[Session] <{}> received {} requests", payload.target, users.len());
    Json(users)
}

#[axum::debug_handler]
async fn get_session(
    Extension(db): Extension<Arc<PgPool>>,
    Json(payload): Json<SearchPayload>
) -> impl IntoResponse {
    let result = sqlx::query!("SELECT * FROM request WHERE target = $1 and account = $2",&payload.target, &payload.account)
        .fetch_optional(db.as_ref())
        .await.unwrap();
    
    if let Some(row) = result {
        info!("[Session] <{}> accepted a session with <{}>", payload.account, payload.target);
        (StatusCode::OK, Json(Some(RequestPayload {
            account: row.account,
            target: row.target,
            ikp: row.ikp,
            ekp: row.ek,
            opk_id: row.id
        })))
    } else {
        warn!("[Session] <{}> failed to accept a session with <{}>", payload.account, payload.target);
        (StatusCode::NOT_FOUND, Json(None::<RequestPayload>))
    }
}