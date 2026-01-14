// Authentication middleware.
// Middleware runs before request handlers and can check if the user is logged in.

use axum::{
    body::Body,
    extract::State,
    http::{header, Request},
    middleware::Next,
    response::Response,
};
use serde::{Deserialize, Serialize};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

use crate::{errors::AppError, state::AppState};

// AuthContext holds information about the authenticated user.
// This gets attached to the request so handlers can access it.
#[derive(Clone, Debug)]
pub struct AuthenticationContext {
    pub user_id: i64,  // The ID of the logged-in user
}

// Claims are the data stored inside the JWT token
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    subject: i64,  // Subject: user ID
    expiration_time: usize,
    issued_at_time: usize,
}

// This middleware function runs before protected routes.
// It checks if the request has a valid JWT token in the Authorization header.
// If valid, it extracts the user ID and attaches it to the request.
// If invalid, it returns an error and stops the request.
pub async fn authenticate(
    State(state): State<AppState>,  // Access to database and config
    mut request: Request<Body>,  // The incoming HTTP request
    next: Next,  // The next middleware/handler to call if auth succeeds
) -> Result<Response, AppError> {
    // Get the Authorization header from the request
    // Format should be: "Authorization: Bearer <token>"
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)  // Get the Authorization header
        .ok_or_else(|| AppError::Unauthorized("Authorization header is missing ".to_string()))?  // Return error if missing
        .to_str()  // Convert header value to string
        .map_err(|_| AppError::Unauthorized("incorrect Authorization header".to_string()))?;  // Return error if invalid

    // Extract the token from "Bearer <token>" format
    let token = auth_header
        .strip_prefix("Bearer ")  // Remove "Bearer " prefix
        .ok_or_else(|| AppError::Unauthorized("Bearer token is expected ".to_string()))?  // Error if not Bearer format
        .trim();  // Remove whitespace

    // Set up token validation rules
    let mut validation = Validation::new(Algorithm::HS256);  // Use HS256 algorithm
    validation.validate_exp = true;  // Check if token has expired

    // Decode and verify the token
    let decoded = decode::<Claims>(
        token,  // The token string
        &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),  // Secret key for verification
        &validation,  // Validation rules
    )
    .map_err(|_| AppError::Unauthorized("invalid or expired token".to_string()))?;  // Return error if invalid

    // If we get here, the token is valid!
    // Attach the user ID to the request so handlers can access it
    request.extensions_mut().insert(AuthenticationContext {
        user_id: decoded.claims.subject,  // Extract user ID from token claims
    });

    // Continue to the next middleware/handler
    Ok(next.run(request).await)
}
