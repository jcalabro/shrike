use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn rust_doc_examples_are_not_ignored() -> Result<(), Box<dyn std::error::Error>> {
    let mut ignored_examples = Vec::new();
    collect_ignored_examples(Path::new("src"), &mut ignored_examples)?;

    assert!(
        ignored_examples.is_empty(),
        "Rust doc examples must be tested. Use `no_run` for examples that compile but must not execute.\n{}",
        ignored_examples
            .iter()
            .map(|(path, line)| format!("{}:{line}", path.display()))
            .collect::<Vec<_>>()
            .join("\n")
    );

    Ok(())
}

fn collect_ignored_examples(
    dir: &Path,
    ignored_examples: &mut Vec<(PathBuf, usize)>,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_ignored_examples(&path, ignored_examples)?;
            continue;
        }

        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }

        let contents = fs::read_to_string(&path)?;
        for (idx, line) in contents.lines().enumerate() {
            let trimmed = line.trim_start();
            if (trimmed.starts_with("//! ```") || trimmed.starts_with("/// ```"))
                && trimmed.contains("ignore")
            {
                ignored_examples.push((path.clone(), idx + 1));
            }
        }
    }

    Ok(())
}
