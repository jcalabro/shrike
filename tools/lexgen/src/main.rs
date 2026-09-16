use std::path::PathBuf;

mod codegen;
mod config;
mod gen_cbor;
mod gen_endpoint;
mod gen_module;
mod gen_shared;
mod gen_struct;
mod gen_union;
mod loader;
mod resolver;
mod util;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (lexdir, config_path, output_root) = parse_args(&args);
    let cfg = config::Config::load(&config_path).unwrap_or_else(|e| {
        eprintln!("Failed to load config: {e}");
        std::process::exit(1);
    });
    eprintln!("Loaded config with {} packages", cfg.packages.len());
    eprintln!("Lexicon dir: {}", lexdir.display());
    let schemas = loader::load_schemas(&lexdir).unwrap_or_else(|e| {
        eprintln!("Failed to load schemas: {e}");
        std::process::exit(1);
    });
    eprintln!("Loaded {} schemas", schemas.len());

    let files = codegen::generate(&cfg, &schemas).unwrap_or_else(|e| {
        eprintln!("Code generation failed: {e}");
        std::process::exit(1);
    });

    for (path, content) in &files {
        let output_path = output_root.join(path);
        if let Some(dir) = output_path.parent() {
            std::fs::create_dir_all(dir).unwrap_or_else(|e| {
                eprintln!("Failed to create dir {}: {e}", dir.display());
                std::process::exit(1);
            });
        }
        let formatted = if path.ends_with(".rs") {
            rustfmt(content)
        } else {
            content.clone()
        };
        std::fs::write(&output_path, formatted).unwrap_or_else(|e| {
            eprintln!("Failed to write {}: {e}", output_path.display());
            std::process::exit(1);
        });
    }

    eprintln!(
        "Generated {} files from {} schemas",
        files.len(),
        schemas.len()
    );
}

fn rustfmt(code: &str) -> String {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let Ok(mut child) = Command::new("rustfmt")
        .arg("--edition=2024")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    else {
        eprintln!("Failed to spawn rustfmt");
        std::process::exit(1);
    };

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(code.as_bytes());
    }

    match child.wait_with_output() {
        Ok(output) if output.status.success() => {
            String::from_utf8(output.stdout).unwrap_or_else(|_| code.to_string())
        }
        _ => code.to_string(),
    }
}

fn parse_args(args: &[String]) -> (PathBuf, PathBuf, PathBuf) {
    let mut lexdir = None;
    let mut config = None;
    let mut output_root = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--lexdir" => {
                i += 1;
                lexdir = args.get(i).map(PathBuf::from);
            }
            "--config" => {
                i += 1;
                config = args.get(i).map(PathBuf::from);
            }
            "--output-root" => {
                i += 1;
                output_root = args.get(i).map(PathBuf::from);
            }
            other => {
                eprintln!("Unknown arg: {other}");
                std::process::exit(1);
            }
        }
        i += 1;
    }
    (
        lexdir.unwrap_or_else(|| {
            eprintln!("--lexdir required");
            std::process::exit(1);
        }),
        config.unwrap_or_else(|| {
            eprintln!("--config required");
            std::process::exit(1);
        }),
        output_root.unwrap_or_else(|| PathBuf::from(".")),
    )
}
