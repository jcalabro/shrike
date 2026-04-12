use shrike_cbor::{Cid, Encoder, Value, decode, encode_text_map};
use shrike_crypto::{Signature, SigningKey, VerifyingKey};
use shrike_syntax::{Did, Tid};

use crate::RepoError;

/// Signed repository commit.
///
/// Version 3 commits require `rev` and `sig`. Version 2 commits (historical)
/// may have both absent, in which case `sig` is `None` and `rev` defaults to
/// `Tid::new(0, 0)`.
#[derive(Debug, Clone)]
pub struct Commit {
    pub did: Did,
    pub version: u32,
    pub rev: Tid,
    pub prev: Option<Cid>,
    pub data: Cid,
    /// Signature over the unsigned commit bytes. `None` for unsigned v2 commits.
    pub sig: Option<Signature>,
}

/// CBOR key order (DAG-CBOR canonical: shorter encoded key first, then lex):
///
///   Full commit: "did"(3), "rev"(3), "sig"(3), "data"(4), "prev"(4), "version"(7)
///   Unsigned:    "did"(3), "rev"(3), "data"(4), "prev"(4), "version"(7)
impl Commit {
    /// Encode all fields except sig to DRISL bytes (for signing/verification).
    ///
    /// Uses a reusable buffer when called from `sign`/`verify` to avoid
    /// repeated allocation.
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, RepoError> {
        let mut buf = Vec::with_capacity(192);
        self.unsigned_bytes_into(&mut buf)?;
        Ok(buf)
    }

    /// Encode unsigned bytes into an existing buffer (avoids allocation).
    #[inline]
    fn unsigned_bytes_into(&self, buf: &mut Vec<u8>) -> Result<(), RepoError> {
        buf.clear();
        let mut enc = Encoder::new(buf);
        let keys: &[&str] = &["did", "rev", "data", "prev", "version"];
        encode_text_map(&mut enc, keys, |enc, key| self.encode_field(enc, key))?;
        Ok(())
    }

    /// Sign this commit, populating the sig field.
    pub fn sign(&mut self, key: &dyn SigningKey) -> Result<(), RepoError> {
        let unsigned = self.unsigned_bytes()?;
        let sig = key.sign(&unsigned)?;
        self.sig = Some(sig);
        Ok(())
    }

    /// Verify the signature against the given public key.
    ///
    /// Returns an error if the commit has no signature (v2 unsigned commits).
    pub fn verify(&self, key: &dyn VerifyingKey) -> Result<(), RepoError> {
        let sig = self
            .sig
            .as_ref()
            .ok_or_else(|| RepoError::Commit("commit has no signature".into()))?;
        let unsigned = self.unsigned_bytes()?;
        key.verify(&unsigned, sig)?;
        Ok(())
    }

    /// Encode the full commit (including sig) to DRISL bytes.
    #[inline]
    pub fn to_cbor(&self) -> Result<Vec<u8>, RepoError> {
        let mut buf = Vec::with_capacity(256);
        let mut enc = Encoder::new(&mut buf);
        let keys: &[&str] = &["did", "rev", "sig", "data", "prev", "version"];
        encode_text_map(&mut enc, keys, |enc, key| self.encode_field(enc, key))?;
        Ok(buf)
    }

    /// Decode a commit from DRISL bytes.
    #[inline]
    pub fn from_cbor(data: &[u8]) -> Result<Self, RepoError> {
        let val = decode(data)?;
        let entries = match val {
            Value::Map(entries) => entries,
            _ => return Err(RepoError::Commit("commit is not a CBOR map".into())),
        };

        let mut did: Option<Did> = None;
        let mut version: Option<u32> = None;
        let mut rev: Option<Tid> = None;
        let mut prev: Option<Cid> = None;
        let mut data_cid: Option<Cid> = None;
        let mut sig: Option<Signature> = None;

        for (key, value) in &entries {
            match *key {
                "did" => {
                    let s = match value {
                        Value::Text(s) => *s,
                        _ => return Err(RepoError::Commit("'did' is not a string".into())),
                    };
                    did = Some(
                        Did::try_from(s)
                            .map_err(|e| RepoError::Commit(format!("invalid did: {e}")))?,
                    );
                }
                "version" => {
                    let v = match value {
                        Value::Unsigned(v) => *v,
                        _ => return Err(RepoError::Commit("'version' is not an integer".into())),
                    };
                    if v != 2 && v != 3 {
                        return Err(RepoError::Commit(format!(
                            "unsupported commit version {v}, expected 2 or 3"
                        )));
                    }
                    version = Some(v as u32);
                }
                "rev" => {
                    let s = match value {
                        Value::Text(s) => *s,
                        _ => return Err(RepoError::Commit("'rev' is not a string".into())),
                    };
                    rev = Some(
                        Tid::try_from(s)
                            .map_err(|e| RepoError::Commit(format!("invalid rev: {e}")))?,
                    );
                }
                "data" => {
                    let c = match value {
                        Value::Cid(c) => *c,
                        _ => return Err(RepoError::Commit("'data' is not a CID".into())),
                    };
                    data_cid = Some(c);
                }
                "prev" => match value {
                    Value::Cid(c) => prev = Some(*c),
                    Value::Null => {}
                    _ => return Err(RepoError::Commit("'prev' is not a CID or null".into())),
                },
                "sig" => {
                    let bytes = match value {
                        Value::Bytes(b) => *b,
                        _ => return Err(RepoError::Commit("'sig' is not bytes".into())),
                    };
                    if bytes.len() != 64 {
                        return Err(RepoError::Commit(format!(
                            "sig must be 64 bytes, got {}",
                            bytes.len()
                        )));
                    }
                    let mut arr = [0u8; 64];
                    arr.copy_from_slice(bytes);
                    sig = Some(Signature::from_bytes(arr));
                }
                _ => {} // ignore unknown fields
            }
        }

        let ver = version.ok_or_else(|| RepoError::Commit("missing 'version'".into()))?;
        let did = did.ok_or_else(|| RepoError::Commit("missing 'did'".into()))?;
        let data_cid = data_cid.ok_or_else(|| RepoError::Commit("missing 'data'".into()))?;

        if ver == 3 && rev.is_none() {
            return Err(RepoError::Commit("v3 commit missing required 'rev'".into()));
        }
        if ver == 3 && sig.is_none() {
            return Err(RepoError::Commit("v3 commit missing required 'sig'".into()));
        }

        // For v2, rev may be absent; default to epoch.
        let rev = rev.unwrap_or_else(|| Tid::new(0, 0));

        Ok(Commit {
            did,
            version: ver,
            rev,
            prev,
            data: data_cid,
            sig,
        })
    }

    /// Encode a single field by key name.
    fn encode_field<W: std::io::Write>(
        &self,
        enc: &mut Encoder<W>,
        key: &str,
    ) -> Result<(), shrike_cbor::CborError> {
        match key {
            "did" => enc.encode_text(self.did.as_str()),
            "rev" => enc.encode_text(&self.rev.to_string()),
            "sig" => match &self.sig {
                Some(s) => enc.encode_bytes(s.as_bytes()),
                None => enc.encode_bytes(&[0u8; 64]),
            },
            "data" => enc.encode_cid(&self.data),
            "prev" => match &self.prev {
                Some(cid) => enc.encode_cid(cid),
                None => enc.encode_null(),
            },
            "version" => enc.encode_u64(u64::from(self.version)),
            _ => Ok(()),
        }
    }
}
