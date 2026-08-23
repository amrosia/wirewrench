//! Simple `key = value` config files shared by `ww` and `ww-server`.
//!
//! Both binaries look for `~/.config/wirewrench/<name>.conf` (honouring
//! `$XDG_CONFIG_HOME`), with `#` comments and blank lines.  Config files are
//! optional — a missing file simply means "no configured defaults".

use std::path::PathBuf;

#[derive(Default)]
pub struct Config {
    entries: Vec<(String, String)>,
}

impl Config {
    /// Load a config file by name (e.g. `"client.conf"`), or `None` if it
    /// doesn't exist / can't be read.
    pub fn load(name: &str) -> Option<Config> {
        let path = config_dir().join(name);
        let content = std::fs::read_to_string(&path).ok()?;
        let mut entries = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match line.split_once('=') {
                Some((k, v)) => {
                    let k = k.trim();
                    let v = v.trim();
                    if k.is_empty() || v.is_empty() {
                        eprintln!("[!] Ignoring malformed line in {}: {line}", path.display());
                    } else {
                        entries.push((k.to_string(), v.to_string()));
                    }
                }
                None => eprintln!("[!] Ignoring malformed line in {}: {line}", path.display()),
            }
        }
        Some(Config { entries })
    }

    /// Get the last value for `key` (single-valued settings).
    #[allow(dead_code)] // used by ww-server; ww only uses `get_all`
    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Get all values for `key`, in file order (multi-valued settings, e.g.
    /// several `identity =` lines).
    #[allow(dead_code)] // used by ww; ww-server only uses `get`
    pub fn get_all(&self, key: &str) -> Vec<String> {
        self.entries
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .collect()
    }
}

/// The wirewrench config directory: `$XDG_CONFIG_HOME/wirewrench`, falling
/// back to `~/.config/wirewrench` (matching the documented location on every
/// platform).
pub fn config_dir() -> PathBuf {
    if let Some(x) = std::env::var_os("XDG_CONFIG_HOME")
        && !x.is_empty()
    {
        return PathBuf::from(x).join("wirewrench");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".config").join("wirewrench");
    }
    PathBuf::from(".")
}

/// Expand a leading `~/` in a path using `$HOME`.
pub fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest).to_string_lossy().into_owned();
    }
    path.to_string()
}
