mod auth;
mod chat;
mod message;
mod workspace;

pub use auth::*;
use axum::response::IntoResponse;
pub use chat::*;
pub use message::*;
pub use workspace::*;

pub async fn index_handler() -> impl IntoResponse {
    "index"
}
