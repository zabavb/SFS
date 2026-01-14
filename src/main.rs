mod config;
mod database;
mod handlers;
mod state;
mod auth;
mod errors;

// Import external libraries
use axum::{middleware, routing::{get, post, delete}, Router};               // Web framework
use tower_http::services::ServeDir;                                         // Serve static files

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok(); // Load env file ignoring errors
    let config = config::Config::from_env();    // Configs from env

    // Create directories if they don't exist
    tokio::fs::create_dir_all(&config.data_path).await?;
    tokio::fs::create_dir_all(&config.files_path).await?;

    let pool = database::connect(&config.db_url).await?;    // Db connection
    database::initialize(&pool).await?;     // Init database

    let state = state::AppState::new(pool, config);     // Init routes state with db and config

    // Non-anonymous routes
    let private_route = Router::new()
        .route("/profile", get(handlers::profile::get_profile))
        .route("/file/upload", post(handlers::files::upload_file))
        .route("/file/:id", get(handlers::files::download_file))
        .route("/file/:id/share", post(handlers::files::share_file))
        .route("/file/:id/share/:username", delete(handlers::files::revoke_share))
        .route("/file/:id/public", post(handlers::files::make_public))
        .route("/file/:id/public", delete(handlers::files::make_private))
        // Middleware checks if the user has a valid JWT token
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::middleware::authenticate,
        ));
        
    let routes = Router::new()
        .route("/health", get(handlers::health::check_health))
        .route("/register", post(handlers::auth::register))
        .route("/login", post(handlers::auth::login))
        .route("/token/refresh", post(handlers::auth::refresh))
        .route("/logout", post(handlers::auth::logout))
        .route("/file/public/:id", get(handlers::files::download_public_file))
        .merge(private_route)
        .with_state(state.clone());
    
    // Fallback route to "home page" (index.html)
    let routes = routes.fallback_service(
        ServeDir::new("static").append_index_html_on_directories(true)
    );

    axum::serve(tokio::net::TcpListener::bind(state.config.address).await?, routes).await?;

    Ok(())  // Like "return 0;"
}