use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use uuid::Uuid;
use bcrypt::{hash, verify, DEFAULT_COST};
use anyhow::Result;

pub type DbPool = Pool<Postgres>;

#[derive(Debug, Clone)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub identity_key: Vec<u8>,
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
    password: &str,
    identity_key: &[u8],
) -> Result<User> {
    let password_hash = hash(password, DEFAULT_COST)?;
    
    let user = sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (username, password_hash, identity_key)
        VALUES ($1, $2, $3)
        RETURNING id, username, password_hash, identity_key
        "#,
        username,
        password_hash,
        identity_key
    )
    .fetch_one(pool)
    .await?;
    
    Ok(user)
}

pub async fn get_user_by_username(
    pool: &DbPool,
    username: &str,
) -> Result<Option<User>> {
    let user = sqlx::query_as!(
        User,
        r#"
        SELECT id, username, password_hash, identity_key
        FROM users
        WHERE username = $1
        "#,
        username
    )
    .fetch_optional(pool)
    .await?;

    Ok(user)
}

pub async fn verify_password(user: &User, password: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, &user.password_hash)
}
