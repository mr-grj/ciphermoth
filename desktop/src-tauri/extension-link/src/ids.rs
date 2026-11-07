//! The extensions the native host and the app accept, and how a browser names
//! its caller when it starts the host: Chromium passes the origin
//! `chrome-extension://<id>/` (Windows adds `--parent-window=<n>`), Firefox
//! passes the manifest path and the extension id.
//!
//! The Chromium id comes from the public `key` in extension/manifest/
//! chromium.json (design decision 34: a throwaway key until the maintainer's
//! own; a test checks the two agree). A public key is public: any unpacked
//! extension can claim this id, so the check only keeps out other store
//! extensions. The pairing is what authenticates the extension.

pub const CHROMIUM_IDS: &[&str] = &["emeejhcdcdnlhejcpeohdafdnkmbaddn"];
pub const FIREFOX_IDS: &[&str] = &["ciphermoth@mr-grj.github.io"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    Chromium(String),
    Firefox(String),
}

impl Caller {
    /// What the host tells the app, which checks it again.
    pub fn origin(&self) -> String {
        match self {
            Caller::Chromium(id) => format!("chrome-extension://{id}/"),
            Caller::Firefox(id) => id.clone(),
        }
    }

    pub fn from_origin(origin: &str) -> Option<Caller> {
        if let Some(id) = origin
            .strip_prefix("chrome-extension://")
            .and_then(|rest| rest.strip_suffix('/'))
        {
            return CHROMIUM_IDS
                .contains(&id)
                .then(|| Caller::Chromium(id.to_string()));
        }
        FIREFOX_IDS
            .contains(&origin)
            .then(|| Caller::Firefox(origin.to_string()))
    }
}

/// The caller named by the host's command line, if it is one of ours.
pub fn caller_from_args(args: &[String]) -> Option<Caller> {
    match args {
        [origin, rest @ ..] if origin.starts_with("chrome-extension://") => {
            if rest.iter().any(|arg| !arg.starts_with("--parent-window=")) || rest.len() > 1 {
                return None;
            }
            Caller::from_origin(origin).filter(|c| matches!(c, Caller::Chromium(_)))
        }
        [_manifest, id] => Caller::from_origin(id).filter(|c| matches!(c, Caller::Firefox(_))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn pinned_callers_only() {
        let chrome = "chrome-extension://emeejhcdcdnlhejcpeohdafdnkmbaddn/";
        assert!(caller_from_args(&args(&[chrome])).is_some());
        assert!(caller_from_args(&args(&[chrome, "--parent-window=1234"])).is_some());
        assert!(caller_from_args(&args(&[
            "/x/com.ciphermoth.desktop.json",
            "ciphermoth@mr-grj.github.io"
        ]))
        .is_some());
        for refused in [
            &["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"][..],
            &["chrome-extension://emeejhcdcdnlhejcpeohdafdnkmbaddn"],
            &["chrome-extension://emeejhcdcdnlhejcpeohdafdnkmbaddn/x"],
            &["chrome-extension://EMEEJHCDCDNLHEJCPEOHDAFDNKMBADDN/"],
            &[chrome, "--other"],
            &[chrome, "--parent-window=1", "--parent-window=2"],
            &["/x/manifest.json", "evil@example.com"],
            &["/x/manifest.json", "ciphermoth@mr-grj.github.io.evil"],
            &[
                "/x/manifest.json",
                "chrome-extension://emeejhcdcdnlhejcpeohdafdnkmbaddn/",
            ],
            &["ciphermoth@mr-grj.github.io"],
            &[],
        ] {
            assert_eq!(caller_from_args(&args(refused)), None, "{refused:?}");
        }
    }

    #[test]
    fn the_chromium_id_matches_the_manifest_key() {
        use base64::Engine;
        use sha2::{Digest, Sha256};
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../extension/manifest/chromium.json"
        );
        let manifest: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let der = base64::engine::general_purpose::STANDARD
            .decode(manifest["key"].as_str().unwrap())
            .unwrap();
        let id: String = Sha256::digest(&der)[..16]
            .iter()
            .flat_map(|b| [b >> 4, b & 15])
            .map(|n| (b'a' + n) as char)
            .collect();
        assert_eq!(CHROMIUM_IDS, &[id.as_str()]);
    }
}
