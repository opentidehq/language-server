//! Points `include_str!` at the shared catalogs, grammars, and highlight queries:
//! the workspace root in a checkout, or the `assets/` copy that
//! `scripts/vendor-crate-assets.py` puts inside a published crate.
fn main() {
    let manifest = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let vendored = manifest.join("assets");
    let root = if vendored.is_dir() {
        vendored
    } else {
        manifest.join("../..")
    };
    println!("cargo:rustc-env=OPENTIDE_ASSETS={}", root.display());
    println!("cargo:rerun-if-changed=build.rs");
}
