//! Server-side key authentication: loading `authorized_keys`-style public keys
//! and verifying a client's signature over the per-connection challenge.

use std::path::Path;

use anyhow::{Context, Result};
use ssh_key::authorized_keys::AuthorizedKeys;
use ssh_key::public::PublicKey;
use ssh_key::HashAlg;

/// Load the authorized public keys from a single file or a folder.
///
/// Parsing semantics match ssh `authorized_keys`: a file holds one key per
/// line (blank lines and `#` comments skipped, option prefixes tolerated); a
/// folder means every regular file at its top level is parsed that way.
///
/// Invalid lines/files are skipped with a warning.  Returns an error if the
/// path is missing/unreadable or no valid key results.
pub fn load_authorized_keys(path: &Path) -> Result<Vec<PublicKey>> {
    let mut keys: Vec<PublicKey> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    let add_file = |p: &Path, keys: &mut Vec<PublicKey>, seen: &mut std::collections::HashSet<String>| -> Result<usize> {
        let content = std::fs::read_to_string(p)
            .with_context(|| format!("cannot read authorized keys file '{}'", p.display()))?;
        let mut n = 0;
        for entry in AuthorizedKeys::new(&content) {
            match entry {
                Ok(e) => {
                    let fp = e.public_key().fingerprint(HashAlg::Sha256).to_string();
                    if seen.insert(fp) {
                        keys.push(e.public_key().clone());
                        n += 1;
                    }
                }
                Err(e) => eprintln!("[!] Skipping invalid key line in '{}': {e}", p.display()),
            }
        }
        Ok(n)
    };

    if path.is_dir() {
        let mut total = 0;
        let dir = std::fs::read_dir(path)
            .with_context(|| format!("cannot read keys directory '{}'", path.display()))?;
        for entry in dir {
            let p = entry?.path();
            if p.is_file() {
                total += add_file(&p, &mut keys, &mut seen)?;
            }
        }
        if total == 0 {
            anyhow::bail!("no valid public keys found in directory '{}'", path.display());
        }
    } else {
        let n = add_file(path, &mut keys, &mut seen)?;
        if n == 0 {
            anyhow::bail!("no valid public keys found in '{}'", path.display());
        }
    }

    Ok(keys)
}

/// Verify a client's signature over `payload` using an authorized public key.
/// Returns `false` on any failure (bad base64, bad signature encoding, or an
/// invalid signature) — never panics.
pub fn verify_signature(pk: &PublicKey, payload: &[u8], sig_b64: &str) -> bool {
    use signature::Verifier;

    let Some(sig_bytes) = wirewrench::auth::b64_decode(sig_b64) else {
        return false;
    };
    let Ok(sig) = ssh_key::Signature::try_from(sig_bytes.as_slice()) else {
        return false;
    };
    Verifier::verify(pk, payload, &sig).is_ok()
}
