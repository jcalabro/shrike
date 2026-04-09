/// Convert an NSID + def name to a Rust type name.
pub fn type_name(nsid: &str, def_name: &str) -> String {
    let parts: Vec<&str> = nsid.split('.').collect();
    let base = if parts.len() >= 2 {
        format!(
            "{}{}",
            capitalize(parts[parts.len() - 2]),
            capitalize(parts[parts.len() - 1])
        )
    } else {
        capitalize(nsid)
    };
    if def_name == "main" {
        base
    } else {
        format!("{}{}", base, capitalize(def_name))
    }
}

/// Convert a camelCase string to snake_case.
pub fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            result.push('_');
        }
        result.push(c.to_ascii_lowercase());
    }
    result
}

/// Sanitize a JSON field name for Rust.
pub fn rust_field_name(json_name: &str) -> String {
    if json_name == "$type" {
        return "r#type".to_string();
    }
    let snake = to_snake_case(json_name);
    if is_rust_keyword(&snake) {
        format!("r#{snake}")
    } else {
        snake
    }
}

fn is_rust_keyword(s: &str) -> bool {
    matches!(
        s,
        "type"
            | "ref"
            | "self"
            | "mod"
            | "use"
            | "fn"
            | "struct"
            | "enum"
            | "impl"
            | "trait"
            | "pub"
            | "let"
            | "mut"
            | "const"
            | "static"
            | "match"
            | "if"
            | "else"
            | "for"
            | "while"
            | "loop"
            | "return"
            | "break"
            | "continue"
            | "move"
            | "box"
            | "where"
            | "async"
            | "await"
            | "dyn"
            | "abstract"
            | "become"
            | "do"
            | "final"
            | "macro"
            | "override"
            | "priv"
            | "typeof"
            | "unsized"
            | "virtual"
            | "yield"
            | "try"
            | "in"
            | "super"
            | "crate"
            | "as"
            | "extern"
            | "true"
            | "false"
    )
}

pub fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().to_string() + chars.as_str(),
    }
}

/// NSID → file name: "app.bsky.feed.post" → "feed_post.rs"
pub fn schema_file_name(nsid: &str) -> String {
    let parts: Vec<&str> = nsid.split('.').collect();
    if parts.len() >= 2 {
        format!(
            "{}_{}.rs",
            parts[parts.len() - 2].to_lowercase(),
            to_snake_case(parts[parts.len() - 1])
        )
    } else {
        format!("{}.rs", to_snake_case(nsid))
    }
}

/// NSID → NSID constant name: "app.bsky.feed.post" → "NSID_FEED_POST"
pub fn nsid_const_name(nsid: &str) -> String {
    let parts: Vec<&str> = nsid.split('.').collect();
    if parts.len() >= 2 {
        format!(
            "NSID_{}",
            parts[parts.len() - 2..]
                .iter()
                .map(|p| p.to_uppercase())
                .collect::<Vec<_>>()
                .join("_")
        )
    } else {
        format!("NSID_{}", nsid.to_uppercase())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_type_name_main() {
        assert_eq!(type_name("app.bsky.feed.post", "main"), "FeedPost");
        assert_eq!(
            type_name("com.atproto.repo.strongRef", "main"),
            "RepoStrongRef"
        );
    }

    #[test]
    fn test_type_name_subdef() {
        assert_eq!(
            type_name("app.bsky.feed.post", "replyRef"),
            "FeedPostReplyRef"
        );
        assert_eq!(
            type_name("app.bsky.actor.defs", "profileViewBasic"),
            "ActorDefsProfileViewBasic"
        );
    }

    #[test]
    fn test_to_snake_case() {
        assert_eq!(to_snake_case("createdAt"), "created_at");
        assert_eq!(to_snake_case("displayName"), "display_name");
        assert_eq!(to_snake_case("mimeType"), "mime_type");
        assert_eq!(to_snake_case("text"), "text");
        assert_eq!(to_snake_case("cid"), "cid");
        assert_eq!(to_snake_case("uri"), "uri");
        assert_eq!(to_snake_case("maxGraphemes"), "max_graphemes");
    }

    #[test]
    fn test_rust_field_name() {
        assert_eq!(rust_field_name("$type"), "r#type");
        assert_eq!(rust_field_name("type"), "r#type");
        assert_eq!(rust_field_name("ref"), "r#ref");
        assert_eq!(rust_field_name("text"), "text");
        assert_eq!(rust_field_name("createdAt"), "created_at");
        assert_eq!(rust_field_name("self"), "r#self");
    }

    #[test]
    fn test_schema_file_name() {
        assert_eq!(schema_file_name("app.bsky.feed.post"), "feed_post.rs");
        assert_eq!(schema_file_name("app.bsky.actor.defs"), "actor_defs.rs");
        assert_eq!(
            schema_file_name("com.atproto.repo.createRecord"),
            "repo_create_record.rs"
        );
        assert_eq!(
            schema_file_name("com.atproto.repo.strongRef"),
            "repo_strong_ref.rs"
        );
    }

    #[test]
    fn test_nsid_const_name() {
        assert_eq!(nsid_const_name("app.bsky.feed.post"), "NSID_FEED_POST");
        assert_eq!(
            nsid_const_name("com.atproto.repo.strongRef"),
            "NSID_REPO_STRONGREF"
        );
    }

    #[test]
    fn test_capitalize() {
        assert_eq!(capitalize("hello"), "Hello");
        assert_eq!(capitalize(""), "");
        assert_eq!(capitalize("a"), "A");
    }
}
