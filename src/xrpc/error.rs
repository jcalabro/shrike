/// Errors returned by the XRPC client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("XRPC error {status}: {error} — {message}")]
    Xrpc {
        status: u16,
        error: String,
        message: String,
    },
    #[error("rate limited, retry after {retry_after:?}")]
    RateLimited {
        retry_after: Option<std::time::Duration>,
    },
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("response too large: {size} bytes exceeds limit {limit}")]
    ResponseTooLarge { size: u64, limit: u64 },
}
