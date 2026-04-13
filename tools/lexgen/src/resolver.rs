use crate::config::Config;
use crate::util;
use shrike::lexicon::split_ref;
use std::collections::HashMap;

/// Resolved reference target.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ResolvedRef {
    pub type_name: String,
    pub module_path: String,
    pub nsid: String,
    pub def_name: String,
}

/// Resolve a ref string from the context of a given schema.
pub fn resolve_ref(
    cfg: &Config,
    context_nsid: &str,
    reference: &str,
    schemas: &HashMap<String, shrike::lexicon::Schema>,
) -> Result<ResolvedRef, String> {
    let (target_nsid, def_name) = split_ref(context_nsid, reference);

    let target_schema = schemas.get(&target_nsid).ok_or_else(|| {
        format!("ref target schema not found: {target_nsid} (from {reference} in {context_nsid})")
    })?;
    if !target_schema.defs.contains_key(def_name) {
        return Err(format!(
            "def not found: {target_nsid}#{def_name} (from {reference} in {context_nsid})"
        ));
    }

    let type_name = util::type_name(&target_nsid, def_name);
    let pkg = cfg
        .find_package(&target_nsid)
        .ok_or_else(|| format!("no package config for: {target_nsid}"))?;
    let module_path = format!("crate::api::{}", pkg.module);

    Ok(ResolvedRef {
        type_name,
        module_path,
        nsid: target_nsid,
        def_name: def_name.to_string(),
    })
}

/// Get the fully qualified Rust type for a ref, relative to the calling module.
#[allow(dead_code)]
pub fn qualified_type(resolved: &ResolvedRef, caller_module: &str) -> String {
    if resolved.module_path == caller_module {
        resolved.type_name.clone()
    } else {
        format!("{}::{}", resolved.module_path, resolved.type_name)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn load_test_data() -> (Config, HashMap<String, shrike::lexicon::Schema>) {
        let cfg = Config::load(std::path::Path::new("../../lexgen.json")).unwrap();
        let schemas = crate::loader::load_schemas(std::path::Path::new("../../lexicons")).unwrap();
        (cfg, schemas)
    }

    #[test]
    fn resolve_local_ref() {
        let (cfg, schemas) = load_test_data();
        let resolved = resolve_ref(&cfg, "app.bsky.feed.post", "#replyRef", &schemas).unwrap();
        assert_eq!(resolved.type_name, "FeedPostReplyRef");
        assert_eq!(resolved.module_path, "crate::api::app::bsky");
        assert_eq!(resolved.nsid, "app.bsky.feed.post");
        assert_eq!(resolved.def_name, "replyRef");
    }

    #[test]
    fn resolve_cross_schema_ref() {
        let (cfg, schemas) = load_test_data();
        let resolved = resolve_ref(
            &cfg,
            "app.bsky.feed.post",
            "com.atproto.repo.strongRef",
            &schemas,
        )
        .unwrap();
        assert_eq!(resolved.type_name, "RepoStrongRef");
        assert_eq!(resolved.module_path, "crate::api::com::atproto");
    }

    #[test]
    fn resolve_hash_ref() {
        let (cfg, schemas) = load_test_data();
        let resolved = resolve_ref(
            &cfg,
            "app.bsky.feed.post",
            "com.atproto.label.defs#selfLabels",
            &schemas,
        )
        .unwrap();
        assert_eq!(resolved.type_name, "LabelDefsSelfLabels");
        assert_eq!(resolved.module_path, "crate::api::com::atproto");
    }

    #[test]
    fn resolve_nonexistent_schema_fails() {
        let (cfg, schemas) = load_test_data();
        assert!(resolve_ref(&cfg, "test", "nonexistent.schema", &schemas).is_err());
    }

    #[test]
    fn resolve_nonexistent_def_fails() {
        let (cfg, schemas) = load_test_data();
        assert!(resolve_ref(&cfg, "test", "app.bsky.feed.post#nonexistent", &schemas).is_err());
    }

    #[test]
    fn qualified_type_same_module() {
        let resolved = ResolvedRef {
            type_name: "FeedPostReplyRef".into(),
            module_path: "crate::api::app::bsky".into(),
            nsid: "app.bsky.feed.post".into(),
            def_name: "replyRef".into(),
        };
        assert_eq!(
            qualified_type(&resolved, "crate::api::app::bsky"),
            "FeedPostReplyRef"
        );
    }

    #[test]
    fn qualified_type_cross_module() {
        let resolved = ResolvedRef {
            type_name: "RepoStrongRef".into(),
            module_path: "crate::api::com::atproto".into(),
            nsid: "com.atproto.repo.strongRef".into(),
            def_name: "main".into(),
        };
        assert_eq!(
            qualified_type(&resolved, "crate::api::app::bsky"),
            "crate::api::com::atproto::RepoStrongRef"
        );
    }

    #[test]
    fn resolve_all_refs_in_post_schema() {
        // Verify ALL refs in app.bsky.feed.post can be resolved
        let (cfg, schemas) = load_test_data();
        let refs = [
            "#replyRef",
            "#entity",
            "#textSlice",
            "app.bsky.richtext.facet",
            "app.bsky.embed.images",
            "app.bsky.embed.video",
            "app.bsky.embed.external",
            "app.bsky.embed.record",
            "app.bsky.embed.recordWithMedia",
            "com.atproto.label.defs#selfLabels",
        ];
        for r in refs {
            resolve_ref(&cfg, "app.bsky.feed.post", r, &schemas)
                .unwrap_or_else(|e| panic!("failed to resolve {r}: {e}"));
        }
    }
}
