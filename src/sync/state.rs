use std::collections::HashMap;
use std::error::Error;
use std::fmt;

use crate::cbor::Cid;
use crate::syntax::Did;

/// Persisted chain head state for a repository.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChainState {
    pub rev: String,
    pub data: Cid,
}

/// Persisted account hosting state for a repository.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HostingState {
    pub active: bool,
    pub status: Option<String>,
    pub seq: i64,
    pub time: String,
}

impl HostingState {
    /// Returns whether a repository should be treated as active.
    ///
    /// Missing hosting state is active by default so existing repos are not
    /// gated until an account event says otherwise.
    pub fn is_active(state: Option<&Self>) -> bool {
        state.map(|state| state.active).unwrap_or(true)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateStoreOperation {
    LoadChain,
    SaveChain,
    LoadHosting,
    SaveHosting,
    Delete,
}

impl fmt::Display for StateStoreOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::LoadChain => "load_chain",
            Self::SaveChain => "save_chain",
            Self::LoadHosting => "load_hosting",
            Self::SaveHosting => "save_hosting",
            Self::Delete => "delete",
        };
        f.write_str(value)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StateStoreError {
    #[error("state store {operation} failed for {did}: {source}")]
    Operation {
        did: Did,
        operation: StateStoreOperation,
        #[source]
        source: Box<dyn Error + Send + Sync + 'static>,
    },
}

impl StateStoreError {
    pub fn operation<E>(did: &Did, operation: StateStoreOperation, source: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self::Operation {
            did: did.clone(),
            operation,
            source: Box::new(source),
        }
    }
}

/// Storage for verifier chain and hosting state.
#[async_trait::async_trait]
pub trait StateStore: Send + Sync {
    async fn load_chain(&self, did: &Did) -> Result<Option<ChainState>, StateStoreError>;
    async fn save_chain(&self, did: &Did, state: ChainState) -> Result<(), StateStoreError>;
    async fn load_hosting(&self, did: &Did) -> Result<Option<HostingState>, StateStoreError>;
    async fn save_hosting(&self, did: &Did, state: HostingState) -> Result<(), StateStoreError>;
    async fn delete(&self, did: &Did) -> Result<(), StateStoreError>;
}

/// In-memory verifier state store.
#[derive(Debug, Default)]
pub struct MemStateStore {
    chains: tokio::sync::RwLock<HashMap<Did, ChainState>>,
    hosting: tokio::sync::RwLock<HashMap<Did, HostingState>>,
}

impl MemStateStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl StateStore for MemStateStore {
    async fn load_chain(&self, did: &Did) -> Result<Option<ChainState>, StateStoreError> {
        Ok(self.chains.read().await.get(did).cloned())
    }

    async fn save_chain(&self, did: &Did, state: ChainState) -> Result<(), StateStoreError> {
        self.chains.write().await.insert(did.clone(), state);
        Ok(())
    }

    async fn load_hosting(&self, did: &Did) -> Result<Option<HostingState>, StateStoreError> {
        Ok(self.hosting.read().await.get(did).cloned())
    }

    async fn save_hosting(&self, did: &Did, state: HostingState) -> Result<(), StateStoreError> {
        self.hosting.write().await.insert(did.clone(), state);
        Ok(())
    }

    async fn delete(&self, did: &Did) -> Result<(), StateStoreError> {
        let mut chains = self.chains.write().await;
        let mut hosting = self.hosting.write().await;
        chains.remove(did);
        hosting.remove(did);
        Ok(())
    }
}
