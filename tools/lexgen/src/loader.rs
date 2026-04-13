use shrike::lexicon::Schema;
use std::collections::HashMap;
use std::path::Path;

/// Load all lexicon schemas from a directory tree.
pub fn load_schemas(dir: &Path) -> Result<HashMap<String, Schema>, Box<dyn std::error::Error>> {
    let mut schemas = HashMap::new();
    load_dir(dir, &mut schemas)?;
    Ok(schemas)
}

fn load_dir(
    dir: &Path,
    schemas: &mut HashMap<String, Schema>,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            load_dir(&path, schemas)?;
        } else if path.extension().is_some_and(|e| e == "json") {
            let data = std::fs::read(&path)?;
            let schema: Schema =
                serde_json::from_slice(&data).map_err(|e| format!("{}: {e}", path.display()))?;
            schemas.insert(schema.id.clone(), schema);
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn load_real_lexicons() {
        let schemas = load_schemas(Path::new("../../lexicons")).unwrap();
        assert!(
            schemas.len() > 300,
            "expected 300+ schemas, got {}",
            schemas.len()
        );
    }

    #[test]
    fn has_expected_schemas() {
        let schemas = load_schemas(Path::new("../../lexicons")).unwrap();
        assert!(schemas.contains_key("app.bsky.feed.post"));
        assert!(schemas.contains_key("com.atproto.repo.createRecord"));
        assert!(schemas.contains_key("app.bsky.actor.defs"));
        assert!(schemas.contains_key("com.atproto.label.defs"));
    }

    #[test]
    fn schema_has_expected_defs() {
        let schemas = load_schemas(Path::new("../../lexicons")).unwrap();
        let post = schemas.get("app.bsky.feed.post").unwrap();
        assert!(post.defs.contains_key("main"));
        assert!(post.defs.contains_key("replyRef"));
        assert!(post.defs.contains_key("textSlice"));
    }

    #[test]
    fn all_schemas_have_ids() {
        let schemas = load_schemas(Path::new("../../lexicons")).unwrap();
        for (id, schema) in &schemas {
            assert_eq!(id, &schema.id, "schema ID mismatch");
            assert_eq!(schema.lexicon, 1, "unexpected lexicon version for {id}");
        }
    }
}
