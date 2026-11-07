//! The browser extension's desktop mode (docs/EXTENSION.md, design section
//! 4.3): shared by the native host (`ciphermoth-native-host`) and the app.

pub mod channel;
pub mod client;
pub mod framing;
pub mod identity;
pub mod ids;
pub mod ipc;
pub mod manifests;
pub mod pairings;
pub mod server;
pub mod wire;
