use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    SqlitePool,  // Connection pool (allows multiple simultaneous database connections)
};
use std::str::FromStr;
use sqlx::FromRow;  // Trait for converting database rows to structs
use sha2::{Digest, Sha256};  // SHA256 hashing algorithm

// Database representation of a user
#[derive(Debug, FromRow)]
pub struct DbUser {
    pub id: i64,
    pub username: String,
    pub password_hash: String,  // Argon2 hash
}

// Database representation of a file
#[derive(Debug, FromRow)]
pub struct DbFile {
    pub id: String,
    pub user_id: i64,
    pub name: String,
    pub storage_path: String,
    pub bytes: i64,
    pub extension: Option<String>,
    pub is_public: i64, // 0 = private, 1 = public (SQLite doesn't have boolean type)
}

// Database representation of a refresh token
#[derive(Debug, sqlx::FromRow)]
pub struct DbRefreshToken {
    pub token_hash: String,  // SHA256 hash of the token
    pub user_id: i64,  // User this token belongs to
    pub expires_at: i64,  // Unix timestamp when token expires
    pub revoked_at: Option<i64>,  // Unix timestamp when revoked (None if still active)
    pub created_at: i64,  // Unix timestamp when token was created
}

// Connect to the SQLite database
// Returns a connection pool that can be used to run queries
pub async fn connect(database_url: &str) -> Result<SqlitePool, sqlx::Error> {
    // Create connection pool with maximum 5 simultaneous connections
    let pool = SqlitePoolOptions::new().max_connections(5);

    // If user provided a sqlite: URL (e.g., "sqlite:data/app.db"), use it as-is
    if database_url.starts_with("sqlite:") {
        return pool.connect(database_url).await;
    }

    // Otherwise treat it as a filesystem path (e.g., "data/app.db")
    // This works better on Windows
    let opts = SqliteConnectOptions::from_str(database_url)?
        .create_if_missing(true);  // Create database file if it doesn't exist

    pool.connect_with(opts).await
}


// Initialize database schema - create all tables if they don't exist
// This is called once when the server starts
pub async fn initialize(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    // Enable foreign key constraints in SQLite (they're off by default)
    sqlx::query("PRAGMA foreign_keys = ON;")
        .execute(pool)
        .await?;

    // Create users table - stores user accounts
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,  -- Auto-incrementing ID
            username TEXT NOT NULL UNIQUE,  -- Username must be unique
            password_hash TEXT NOT NULL,  -- Hashed password (never store plain text!)
            created_at TEXT NOT NULL DEFAULT (datetime('now'))  -- Account creation timestamp
        );
        "#,
    )
    .execute(pool)
    .await?;

    // Create files table - stores file metadata (actual files are on disk)
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,  -- UUID string
            user_id INTEGER NOT NULL,  -- User who owns this file
            name TEXT NOT NULL,  -- Original filename from upload
            storage_path TEXT NOT NULL,  -- Path to file on disk
            bytes INTEGER NOT NULL,  -- File size in bytes
            extension TEXT,  -- MIME type (e.g., "image/png")
            is_public INTEGER NOT NULL DEFAULT 0,  -- 0=private, 1=public
            created_at TEXT NOT NULL DEFAULT (datetime('now')),  -- Upload timestamp
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE  -- If user deleted, delete their files
        );
        "#,
    )
    .execute(pool)
    .await?;

    // Create permissions table - tracks which files are shared with which users
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS permissions (
            file_id TEXT NOT NULL,  -- File being shared
            user_id INTEGER NOT NULL,  -- User who has access
            created_at TEXT NOT NULL DEFAULT (datetime('now')),  -- When sharing was granted
            PRIMARY KEY (file_id, user_id),  -- Each file-user pair is unique
            FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,  -- If file deleted, remove permissions
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE  -- If user deleted, remove their permissions
        );
        "#,
    )
    .execute(pool)
    .await?;

    // Create tokens table - stores refresh token hashes for authentication
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tokens (
            token_hash TEXT PRIMARY KEY,  -- SHA256 hash of the token (never store plain tokens!)
            user_id INTEGER NOT NULL,  -- User this token belongs to
            expires_at INTEGER NOT NULL,  -- Unix timestamp when token expires
            revoked_at INTEGER,  -- Unix timestamp when token was revoked (NULL if still active)
            created_at INTEGER NOT NULL,  -- Unix timestamp when token was created
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE  -- If user deleted, delete their tokens
        );
        "#,
    )
    .execute(pool)
    .await?;

    // Create index on user_id for faster lookups
    // Indexes speed up queries like "find all tokens for user X"
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON tokens(user_id);")
        .execute(pool)
        .await?;

    Ok(())
}

// Create a new user in the database
// Returns the new user's ID
pub async fn insert_user(
    pool: &SqlitePool,
    username: &str,  // Username (must be unique)
    password_hash: &str,  // Hashed password (Argon2 hash)
) -> Result<i64, sqlx::Error> {
    // Insert new user into database
    // ? = placeholder for parameter (prevents SQL injection)
    let result = sqlx::query(
        r#"
        INSERT INTO users (username, password_hash)
        VALUES (?, ?);
        "#,
    )
    .bind(username)  // Bind first parameter
    .bind(password_hash)  // Bind second parameter
    .execute(pool)  // Execute query
    .await?;  // Wait for completion

    // Return the ID of the newly created user
    Ok(result.last_insert_rowid())
}

// Get user by username
// Returns Option<DbUser> - Some(user) if found, None if not found
pub async fn get_user_by_username(
    pool: &SqlitePool,
    username: &str,
) -> Result<Option<DbUser>, sqlx::Error> {
    // Query database for user with matching username
    // query_as automatically converts database row to DbUser struct
    let user = sqlx::query_as::<_, DbUser>(
        r#"
        SELECT id, username, password_hash
        FROM users
        WHERE username = ?;
        "#,
    )
    .bind(username)
    .fetch_optional(pool)  // fetch_optional returns None if no rows found
    .await?;

    Ok(user)
}


// Get basic user info (ID and username) by user ID
// Returns Option<(id, username)> - Some((id, username)) if found, None if not found
// This doesn't return password_hash (for security)
pub async fn get_user_by_id(
    pool: &SqlitePool,
    user_id: i64,
) -> Result<Option<(i64, String)>, sqlx::Error> {
    // Query for user ID and username only (not password)
    let row = sqlx::query_as::<_, (i64, String)>(
        r#"
        SELECT id, username
        FROM users
        WHERE id = ?;
        "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}
// Insert file metadata into database
// Note: The actual file is stored on disk, only metadata goes in the database
pub async fn insert_file(
    pool: &SqlitePool,
    id: &str,  // Unique file ID (UUID)
    user_id: i64,  // User who owns this file
    name: &str,  // Original filename from upload
    storage_path: &str,  // Path to file on disk
    bytes: i64,  // File size in bytes
    extension: Option<&str>,  // MIME type (optional)
) -> Result<(), sqlx::Error> {
    // Insert file record into database
    sqlx::query(
        r#"
        INSERT INTO files (id, user_id, name, storage_path, bytes, extension, is_public)
        VALUES (?, ?, ?, ?, ?, ?, 0);
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .bind(storage_path)
    .bind(bytes)
    .bind(extension)  // Option<&str> can be None, which becomes NULL in database
    .execute(pool)
    .await?;

    Ok(())
}

/* // List all files owned by a specific user
// Returns Vec<DbFile> - list of files (empty list if user has no files)
// Files are ordered by creation date (newest first)
pub async fn list_files_for_owner(
    pool: &SqlitePool,
    user_id: i64,
) -> Result<Vec<DbFile>, sqlx::Error> {
    let rows = sqlx::query_as::<_, DbFile>(
        r#"
        SELECT id, user_id, name, storage_path, bytes, extension, is_public
        FROM files
        WHERE user_id = ?
        ORDER BY created_at DESC;  -- Newest files first
        "#,
    )
    .bind(user_id)
    .fetch_all(pool)  // fetch_all returns Vec (empty if no rows)
    .await?;

    Ok(rows)
} */


// Get file metadata by file ID
// Returns Option<DbFile> - Some(file) if found, None if not found
pub async fn get_file_by_id(pool: &SqlitePool, file_id: &str) -> Result<Option<DbFile>, sqlx::Error> {
    let row = sqlx::query_as::<_, DbFile>(
        r#"
        SELECT id, user_id, name, storage_path, bytes, extension, is_public
        FROM files
        WHERE id = ?;
        "#
    )
    .bind(file_id)
    .fetch_optional(pool)  // Returns None if no file found
    .await?;

    Ok(row)
}

// Check if a user has permission to access a file (via sharing)
// Returns true if permission exists, false otherwise
pub async fn has_file_permission(
    pool: &SqlitePool,
    file_id: &str,
    user_id: i64,
) -> Result<bool, sqlx::Error> {
    // Query for first matching permission record
    let exists: Option<(i64,)> = sqlx::query_as(
        r#"
        SELECT 1
        FROM permissions
        WHERE file_id = ? AND user_id = ?
        LIMIT 1;  -- Stop after finding first match (more efficient)
        "#
    )
    .bind(file_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    // If exists.is_some(), permission exists; if None, no permission
    Ok(exists.is_some())
}

pub async fn get_user_id_by_username(
    pool: &SqlitePool,
    username: &str,
) -> Result<Option<i64>, sqlx::Error> {
    let row: Option<(i64,)> = sqlx::query_as(
        r#"
        SELECT id
        FROM users
        WHERE username = ?;
        "#,
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;

    // Extract the ID from the tuple (row.map(|t| t.0) gets first element)
    Ok(row.map(|t| t.0))
}

// Grant file access permission to a user (share file)
// Returns number of rows affected (0 if already shared, 1 if newly shared)
pub async fn insert_permission(
    pool: &SqlitePool,
    file_id: &str,
    user_id: i64,
) -> Result<u64, sqlx::Error> {
    // INSERT OR IGNORE means: if permission already exists, do nothing (don't error)
    // This requires UNIQUE(file_id, user_id) constraint (which we have via PRIMARY KEY)
    let res = sqlx::query(
        r#"
        INSERT OR IGNORE INTO permissions (file_id, user_id)
        VALUES (?, ?);
        "#,
    )
    .bind(file_id)
    .bind(user_id)
    .execute(pool)
    .await?;

    // Return number of rows affected (0 = already existed, 1 = newly inserted)
    Ok(res.rows_affected())
}

// Revoke file access permission (unshare file)
// Returns number of rows deleted (0 if permission didn't exist, 1 if deleted)
pub async fn delete_permission(
    pool: &SqlitePool,
    file_id: &str,
    user_id: i64,
) -> Result<u64, sqlx::Error> {
    let res = sqlx::query(
        r#"
        DELETE FROM permissions
        WHERE file_id = ? AND user_id = ?;
        "#,
    )
    .bind(file_id)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(res.rows_affected())
}

// Set file public/private status
// Returns number of rows updated (should be 1 if file exists)
pub async fn make_file_public_or_private(
    pool: &SqlitePool,
    file_id: &str,
    is_public: bool,
) -> Result<u64, sqlx::Error> {
    // Convert bool to integer (SQLite doesn't have boolean type)
    let v = if is_public { 1 } else { 0 };

    let res = sqlx::query(
        r#"
        UPDATE files
        SET is_public = ?
        WHERE id = ?;
        "#,
    )
    .bind(v)
    .bind(file_id)
    .execute(pool)
    .await?;

    Ok(res.rows_affected())
}

// Get refresh token by its hash
// Returns Option<DbRefreshToken> - Some(token) if found, None if not found
pub async fn get_refresh_token_by_hash(
    pool: &SqlitePool,
    token_hash: &str,
) -> Result<Option<DbRefreshToken>, sqlx::Error> {
    let row = sqlx::query_as::<_, DbRefreshToken>(
        r#"
        SELECT token_hash, user_id, expires_at, revoked_at, created_at
        FROM tokens
        WHERE token_hash = ?
        LIMIT 1;
        "#,
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

// Create a new refresh token (generate UUID, hash it, store hash in DB)
// Returns the plain token (hashed version is stored in database)
pub async fn create_refresh_token(
    pool: &SqlitePool,
    user_id: i64,
    ttl_secs: i64,  // Time-to-live in seconds
) -> Result<String, sqlx::Error> {
    // Generate random UUID as token
    let token = uuid::Uuid::new_v4().to_string();
    // Hash the token before storing
    let token_hash = sha256_hex(&token);
    let now = unix_now();
    let expires_at = now + ttl_secs;

    // Store hash in database
    insert_refresh_token(pool, user_id, &token_hash, expires_at).await?;
    // Return plain token (client needs this, hash is in DB)
    Ok(token)
}

// Insert a refresh token hash into the database
// Note: We store the HASH of the token, not the token itself (for security)
pub async fn insert_refresh_token(
    pool: &SqlitePool,
    user_id: i64,
    token_hash: &str,  // SHA256 hash of the token
    expires_at: i64,  // Unix timestamp when token expires
) -> Result<(), sqlx::Error> {
    let now = unix_now();

    // Insert token hash into database
    sqlx::query(
        r#"
        INSERT INTO tokens (token_hash, user_id, expires_at, created_at)
        VALUES (?, ?, ?, ?);
        "#,
    )
    .bind(token_hash)
    .bind(user_id)
    .bind(expires_at)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}
// Revoke a refresh token (mark it as revoked)
// Returns number of rows updated (should be 1 if token exists and wasn't already revoked)
pub async fn revoke_refresh_token(
    pool: &SqlitePool,
    token_hash: &str,
    revoked_at: i64,  // Unix timestamp when revoked
) -> Result<u64, sqlx::Error> {
    // Only revoke if not already revoked (revoked_at IS NULL)
    let res = sqlx::query(
        r#"
        UPDATE tokens
        SET revoked_at = ?
        WHERE token_hash = ? AND revoked_at IS NULL;
        "#,
    )
    .bind(revoked_at)
    .bind(token_hash)
    .execute(pool)
    .await?;

    Ok(res.rows_affected())
}

// Revoke a refresh token by its raw (plain) token value
// This hashes the token first, then revokes it
// Used by the logout endpoint
pub async fn revoke_refresh_token_by_raw(
    pool: &SqlitePool,
    raw_refresh_token: &str,  // Plain token (will be hashed)
) -> Result<u64, sqlx::Error> {
    // Hash the token to look it up in database
    let token_hash = sha256_hex(raw_refresh_token);

    let now = {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    };

    // Revoke the token
    let res = sqlx::query(
        r#"
        UPDATE tokens
        SET revoked_at = ?
        WHERE token_hash = ? AND revoked_at IS NULL;
        "#,
    )
    .bind(now)
    .bind(token_hash)
    .execute(pool)
    .await?;

    Ok(res.rows_affected())
}

// Hash a string using SHA256 and return hexadecimal representation
// Used to hash refresh tokens before storing in database
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();  // Create SHA256 hasher
    hasher.update(input.as_bytes());  // Feed input bytes to hasher
    let out = hasher.finalize();  // Get hash result
    hex::encode(out)  // Convert to hexadecimal string
}

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()  // Should never fail
        .as_secs() as i64
}

