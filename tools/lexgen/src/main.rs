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
    let (lexdir, config_path) = parse_args(&args);
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
        if let Some(dir) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(dir).unwrap_or_else(|e| {
                eprintln!("Failed to create dir {}: {e}", dir.display());
                std::process::exit(1);
            });
        }
        std::fs::write(path, content).unwrap_or_else(|e| {
            eprintln!("Failed to write {path}: {e}");
            std::process::exit(1);
        });
    }

    eprintln!(
        "Generated {} files from {} schemas",
        files.len(),
        schemas.len()
    );
}

fn parse_args(args: &[String]) -> (PathBuf, PathBuf) {
    let mut lexdir = None;
    let mut config = None;
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
    )
}
