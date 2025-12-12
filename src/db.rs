use anyhow::Result;
use bcrypt::{hash, DEFAULT_COST};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

pub type DbPool = Pool<Postgres>;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub password_hash: String,
    pub identity_key: Vec<u8>,
    pub avatar_url: Option<String>,
    pub bio: Option<String>,
    pub created_at: Option<chrono::NaiveDateTime>,
    pub last_seen: Option<chrono::NaiveDateTime>,
}

pub async fn create_pool(database_url: &str) -> Result<DbPool> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?;
    Ok(pool)
}

pub async fn create_user(
    pool: &DbPool,
    username: &str,
    display_name: &str,
    password: &str,
    identity_key: &[u8],
) -> Result<User> {
    let password_hash = hash(password, DEFAULT_COST)?;

    let user = sqlx::query_as::<_, User>(
        r#"
        INSERT INTO users (username, display_name, password_hash, identity_key)
        VALUES ($1, $2, $3, $4)
        RETURNING id, username, display_name, password_hash, identity_key, 
                  avatar_url, bio, created_at, last_seen
           "#,
    )
    .bind(username)
    .bind(display_name)
    .bind(password_hash)
    .bind(identity_key)
    .fetch_one(pool)
    .await?;

    Ok(user)
}

pub async fn get_user_by_username(pool: &DbPool, username: &str) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        r#"
        SELECT id, username, display_name, password_hash, identity_key,
               avatar_url, bio, created_at, last_seen
        FROM users
        WHERE username = $1
        "#,
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

pub async fn get_user_by_id(pool: &DbPool, user_id: &Uuid) -> Result<Option<User>> {
    let user = sqlx::query_as::<_, User>(
        r#"
        SELECT id, username, display_name, password_hash, identity_key,
               avatar_url, bio, created_at, last_seen
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

pub async fn search_users_by_display_name(
    pool: &DbPool,
    query: &str,
) -> Result<Vec<PublicUserInfo>> {
    let users = sqlx::query_as::<_, PublicUserInfo>(
        r#"
        SELECT id, username, display_name, avatar_url, bio
        FROM users
        WHERE display_name ILIKE $1
        LIMIT 20
        "#,
    )
    .bind(format!("%{}%", query))
    .fetch_all(pool)
    .await?;

    Ok(users)
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PublicUserInfo {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub bio: Option<String>,
}

pub async fn verify_password(user: &User, password: &str) -> Result<bool> {
    Ok(bcrypt::verify(password, &user.password_hash)?)
}

pub async fn get_public_key(pool: &DbPool, username: &str) -> Result<Option<Vec<u8>>> {
    let result = sqlx::query!(
        r#"
        SELECT identity_key
        FROM users
        WHERE username = $1
        "#,
        username
    )
    .fetch_optional(pool)
    .await?;

    Ok(result.map(|r| r.identity_key))
}

