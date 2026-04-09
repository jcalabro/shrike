use std::sync::Arc;

use anyhow::{Context, Result};
use serde::Serialize;

use ratproto_syntax::{Did, Handle};
use ratproto_xrpc::{AuthInfo, Client};

use crate::session::{self, Session};

#[derive(clap::Subcommand)]
pub enum Command {
    /// Login with app password
    Login(LoginArgs),
    /// Login with OAuth (opens browser)
    OauthLogin(OauthLoginArgs),
    /// Delete stored session
    Logout,
    /// Show current session status
    Status(StatusArgs),
}

#[derive(clap::Args)]
pub struct LoginArgs {
    /// Handle, DID, or email
    pub identifier: String,
    /// App password
    pub password: String,
    /// Service host URL
    #[arg(long, default_value = "https://bsky.social")]
    pub host: String,
}

#[derive(clap::Args)]
pub struct OauthLoginArgs {
    /// Handle or DID
    pub identifier: String,
    /// Local port for OAuth callback (0 = auto)
    #[arg(long, default_value = "0")]
    pub port: u16,
}

#[derive(clap::Args)]
pub struct StatusArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Login(args) => login(args).await,
        Command::OauthLogin(args) => oauth_login(args).await,
        Command::Logout => logout().await,
        Command::Status(args) => status(args),
    }
}

async fn login(args: LoginArgs) -> Result<()> {
    let client = Client::new(&args.host);
    let auth = client
        .create_session(&args.identifier, &args.password)
        .await
        .context("login failed")?;

    let sess = Session {
        host: args.host,
        access_jwt: auth.access_jwt.clone(),
        refresh_jwt: auth.refresh_jwt.clone(),
        handle: auth.handle.to_string(),
        did: auth.did.to_string(),
    };
    session::save(&sess).context("failed to save session")?;

    println!("logged in as {} ({})", sess.handle, sess.did);
    Ok(())
}

async fn oauth_login(args: OauthLoginArgs) -> Result<()> {
    use ratproto_oauth::{
        AuthorizeOptions, CallbackParams, ClientMetadata, MemorySessionStore, MemoryStateStore,
        OAuthClient, OAuthClientConfig,
    };
    use tokio::sync::oneshot;

    // Bind a local server to receive the OAuth callback.
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", args.port))
        .await
        .context("failed to bind local callback server")?;
    let local_addr = listener
        .local_addr()
        .context("failed to get local address")?;
    let redirect_uri = format!("http://127.0.0.1:{}", local_addr.port());

    // For CLI/loopback OAuth clients, AT Protocol accepts "http://localhost"
    // as a special client_id that doesn't require a fetchable metadata document.
    let client_id = "http://localhost".to_string();

    let state_store = MemoryStateStore::new();
    let session_store = MemorySessionStore::new();

    let oauth = OAuthClient::new(OAuthClientConfig {
        metadata: ClientMetadata {
            client_id: client_id.clone(),
            redirect_uris: vec![redirect_uri.clone()],
            scope: "atproto".into(),
            token_endpoint_auth_method: "none".into(),
            ..Default::default()
        },
        session_store: Box::new(session_store),
        state_store: Box::new(state_store),
        signing_key: None,
        skip_issuer_verification: false,
    });

    // Start the authorize flow.
    let result = oauth
        .authorize(AuthorizeOptions {
            input: args.identifier.clone(),
            redirect_uri: redirect_uri.clone(),
            scope: None,
            state: None,
        })
        .await
        .context("OAuth authorization failed")?;

    let expected_state = result.state.clone();

    println!("Open this URL in your browser to authorize:");
    println!();
    println!("  {}", result.url);
    println!();
    println!("Waiting for callback on {}...", local_addr);

    // Set up a oneshot channel to receive the callback parameters.
    let (tx, rx) = oneshot::channel::<(String, String, Option<String>)>();
    let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));

    // Build a tiny axum server to catch the callback.
    let app = axum::Router::new().route(
        "/",
        axum::routing::get({
            let tx = Arc::clone(&tx);
            move |query: axum::extract::Query<std::collections::HashMap<String, String>>| {
                let tx = Arc::clone(&tx);
                async move {
                    let code = query.get("code").cloned().unwrap_or_default();
                    let state = query.get("state").cloned().unwrap_or_default();
                    let iss = query.get("iss").cloned();

                    if let Some(sender) = tx.lock().await.take() {
                        let _ = sender.send((code, state, iss));
                    }

                    axum::response::Html(
                        "<html><body><h1>Authorization complete</h1>\
                         <p>You can close this tab and return to your terminal.</p>\
                         </body></html>",
                    )
                }
            }
        }),
    );

    // Spawn the server — it will stop after receiving one callback.
    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    // Wait for the callback (with timeout).
    let (code, state, iss) = tokio::time::timeout(std::time::Duration::from_secs(300), rx)
        .await
        .context("OAuth callback timed out (5 minutes)")??;

    // Abort the server.
    server_handle.abort();

    if state != expected_state {
        anyhow::bail!("OAuth state mismatch — possible CSRF attack");
    }

    // Exchange the code for tokens.
    let oauth_session = oauth
        .callback(CallbackParams { code, state, iss })
        .await
        .context("OAuth token exchange failed")?;

    // Save the OAuth session to disk.
    session::save_oauth(&oauth_session).context("failed to save OAuth session")?;

    println!(
        "logged in via OAuth as {} ({})",
        args.identifier, oauth_session.token_set.sub
    );
    Ok(())
}

async fn logout() -> Result<()> {
    // Best-effort server-side session deletion for app password.
    if let Ok(sess) = session::load() {
        let handle = Handle::try_from(sess.handle.as_str());
        let did = Did::try_from(sess.did.as_str());
        if let (Ok(handle), Ok(did)) = (handle, did) {
            let auth = AuthInfo {
                access_jwt: sess.access_jwt,
                refresh_jwt: sess.refresh_jwt,
                handle,
                did,
            };
            let client = Client::with_auth(&sess.host, auth);
            let _ = client.delete_session().await;
        }
    }

    session::delete()?;
    session::delete_oauth()?;
    println!("logged out");
    Ok(())
}

fn status(args: StatusArgs) -> Result<()> {
    match session::require()? {
        session::ActiveSession::AppPassword(sess) => {
            if args.json {
                #[derive(Serialize)]
                struct Output {
                    auth_type: String,
                    host: String,
                    handle: String,
                    did: String,
                }
                let output = Output {
                    auth_type: "app_password".into(),
                    host: sess.host,
                    handle: sess.handle,
                    did: sess.did,
                };
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("auth:    app_password");
                println!("host:    {}", sess.host);
                println!("handle:  {}", sess.handle);
                println!("did:     {}", sess.did);
            }
        }
        session::ActiveSession::OAuth(sess) => {
            if args.json {
                #[derive(Serialize)]
                struct Output {
                    auth_type: String,
                    issuer: String,
                    did: String,
                    scope: String,
                }
                let output = Output {
                    auth_type: "oauth".into(),
                    issuer: sess.token_set.issuer.clone(),
                    did: sess.token_set.sub.clone(),
                    scope: sess.token_set.scope.clone(),
                };
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("auth:    oauth");
                println!("issuer:  {}", sess.token_set.issuer);
                println!("did:     {}", sess.token_set.sub);
                println!("scope:   {}", sess.token_set.scope);
            }
        }
    }

    Ok(())
}
