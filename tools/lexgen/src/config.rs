use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub packages: Vec<PackageConfig>,
}

#[derive(Debug, Deserialize)]
pub struct PackageConfig {
    pub prefix: String,
    pub module: String,
    pub out_dir: String,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let data = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&data)?)
    }

    pub fn find_package(&self, nsid: &str) -> Option<&PackageConfig> {
        self.packages
            .iter()
            .filter(|p| nsid.starts_with(&p.prefix))
            .max_by_key(|p| p.prefix.len())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn load_config() {
        let cfg = Config::load(Path::new("../../lexgen.json")).unwrap();
        assert_eq!(cfg.packages.len(), 4);
    }

    #[test]
    fn find_package_longest_match() {
        let cfg = Config::load(Path::new("../../lexgen.json")).unwrap();
        let pkg = cfg.find_package("app.bsky.feed.post").unwrap();
        assert_eq!(pkg.prefix, "app.bsky");
        assert_eq!(pkg.module, "app::bsky");
    }

    #[test]
    fn find_package_no_match() {
        let cfg = Config::load(Path::new("../../lexgen.json")).unwrap();
        assert!(cfg.find_package("unknown.prefix").is_none());
    }
}
