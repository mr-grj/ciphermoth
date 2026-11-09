# Vendored crates

Patched copies of dependencies whose fix is not released for the version our
dependencies require. Each is wired in by `[patch.crates-io]` in
`../Cargo.toml`. Remove a copy (and its patch entry) as soon as the dependency
tree can use a fixed release.

## glib-0.18.5

Tauri 2 (tauri, wry, tao, muda, webkit2gtk 2.0) requires `gtk` 0.18 and so
`glib` 0.18, but RUSTSEC-2024-0429 / GHSA-wrw7-89jp-8q8g (unsound
`VariantStrIter`, a NULL pointer read) is fixed only in `glib` 0.20.

This is the published `glib` 0.18.5 crate with two changes:

- `src/variant_iter.rs` carries the upstream fix (gtk-rs/gtk-rs-core#1343:
  the out-argument passed as `&mut p`);
- `src/lib.rs` allows all warnings and clippy lints at the crate root, because
  Cargo lints a path dependency like our own code (a crates.io crate gets
  `--cap-lints allow`), and `cargo clippy --workspace -- -D warnings` would
  otherwise fail on third-party code.

It is built only for Linux (GTK). MIT licensed, see `LICENSE` and `COPYRIGHT`.

Check: `diff -r ~/.cargo/registry/src/*/glib-0.18.5 glib-0.18.5` shows only
those changes (plus the registry's `.cargo-ok` and `.cargo_vcs_info.json`).
