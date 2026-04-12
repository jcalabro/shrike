use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// App-password session (from `account login`).
#[derive(Debug, Serialize, Deserialize)]
pub struct Session {
    pub host: String,
    pub access_jwt: String,
    pub refresh_jwt: String,
    pub handle: String,
    pub did: String,
}

/// What type of session is active.
pub enum ActiveSession {
    AppPassword(Session),
    OAuth(shrike_oauth::Session),
}

fn config_dir() -> Result<PathBuf> {
    dirs::config_dir().context("could not determine config directory")
}

// ---------------------------------------------------------------------------
// App-password session (session.json)
// ---------------------------------------------------------------------------

pub fn session_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("rat").join("session.json"))
}

pub fn load() -> Result<Session> {
    let path = session_path()?;
    let data = fs::read_to_string(&path)
        .with_context(|| format!("failed to read session file: {}", path.display()))?;
    let session: Session = serde_json::from_str(&data).context("failed to parse session file")?;
    Ok(session)
}

pub fn save(session: &Session) -> Result<()> {
    let path = session_path()?;
    write_json_file(&path, session)
}

pub fn delete() -> Result<()> {
    let path = session_path()?;
    delete_file(&path)
}

// ---------------------------------------------------------------------------
// OAuth session (oauth_session.json)
// ---------------------------------------------------------------------------

pub fn oauth_session_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("rat").join("oauth_session.json"))
}

pub fn load_oauth() -> Result<shrike_oauth::Session> {
    let path = oauth_session_path()?;
    let data = fs::read_to_string(&path)
        .with_context(|| format!("failed to read OAuth session: {}", path.display()))?;
    let session: shrike_oauth::Session =
        serde_json::from_str(&data).context("failed to parse OAuth session")?;
    Ok(session)
}

pub fn save_oauth(session: &shrike_oauth::Session) -> Result<()> {
    let path = oauth_session_path()?;
    write_json_file(&path, session)
}

pub fn delete_oauth() -> Result<()> {
    let path = oauth_session_path()?;
    delete_file(&path)
}

// ---------------------------------------------------------------------------
// Unified session access (prefer OAuth, fall back to app password)
// ---------------------------------------------------------------------------

/// Load the best available session. Prefers OAuth over app password.
pub fn require() -> Result<ActiveSession> {
    if let Ok(oauth) = load_oauth() {
        return Ok(ActiveSession::OAuth(oauth));
    }
    if let Ok(app) = load() {
        return Ok(ActiveSession::AppPassword(app));
    }
    anyhow::bail!("not logged in (run 'rat account login' or 'rat account oauth-login' first)")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn write_json_file<T: Serialize>(path: &PathBuf, data: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory: {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(data).context("failed to serialize")?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to write: {}", path.display()))?;
    file.write_all(json.as_bytes())
        .context("failed to write data")?;
    Ok(())
}

fn delete_file(path: &PathBuf) -> Result<()> {
    if path.exists() {
        fs::remove_file(path).with_context(|| format!("failed to delete: {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn session_round_trip() {
        let session = Session {
            host: "https://bsky.social".into(),
            access_jwt: "access123".into(),
            refresh_jwt: "refresh456".into(),
            handle: "alice.bsky.social".into(),
            did: "did:plc:abc123".into(),
        };
        let json = serde_json::to_string_pretty(&session).unwrap();
        let parsed: Session = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.host, "https://bsky.social");
        assert_eq!(parsed.access_jwt, "access123");
        assert_eq!(parsed.refresh_jwt, "refresh456");
        assert_eq!(parsed.handle, "alice.bsky.social");
        assert_eq!(parsed.did, "did:plc:abc123");
    }
}
