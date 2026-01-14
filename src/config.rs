use std::{net::SocketAddr, path::PathBuf};

#[derive(Debug, Clone)]
pub struct Config {
    pub address: SocketAddr,
    pub db_url: String,
    pub data_path: PathBuf,
    pub files_path: PathBuf,
    pub jwt_secret: String,
    pub access_ttl_secs: i64,
    pub refresh_ttl_secs: i64,
}

impl Config {
    pub fn from_env() -> Self {
        let address: SocketAddr = std::env::var("ADDRESS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "127.0.0.1:8080".parse().unwrap());

        let db_url = std::env::var("DB_URL")
            .unwrap_or_else(|_| "data/server.db".to_string()); // use this default value instead
        
        let data_path = PathBuf::from("data");

        let files_path = std::env::var("FILES_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("data/files"));

        let jwt_secret = std::env::var("JWT_SECRET")
            .unwrap_or_else(|_| "default-secret-key-which-shouldn't-be-used".to_string());

        let access_ttl_secs: i64 = std::env::var("ACCESS_TTL_SECS")
            .ok().and_then(|v| v.parse().ok())
            .unwrap_or(60 * 60 * 3); // 3 hours

        let refresh_ttl_secs: i64 = std::env::var("REFRESH_TTL_SECS")
            .ok().and_then(|v| v.parse().ok())
            .unwrap_or(60 * 60 * 24 * 2); // 2 days

        // Create and return a new Config struct with all the values
        Self {
            db_url,
            address,
            files_path,
            data_path,
            jwt_secret,
            access_ttl_secs,
            refresh_ttl_secs,
        }
    }
}
