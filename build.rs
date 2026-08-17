//! Regenerates `include/tamga.h` from this crate's `extern "C"` API via
//! cbindgen on every build.
//!
//! The committed `include/tamga.h` is the last-generated snapshot of the real
//! exported ABI, checked in so downstream consumers can build without running
//! Rust tooling. CI's header-freshness gate (`.github/workflows/ci.yml`) runs
//! a build and then `git diff --exit-code include/tamga.h` — a
//! drifted/uncommitted header fails CI, so regenerate and commit the header
//! alongside any change to an `extern "C"` signature or its doc comment.

use std::env;

fn main() {
    let crate_dir =
        env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is always set by cargo");

    let config = match cbindgen::Config::from_file("cbindgen.toml") {
        Ok(config) => config,
        Err(error) => {
            // Fail loudly rather than silently falling back to cbindgen's
            // built-in defaults — a misconfigured cbindgen.toml producing a
            // header that quietly doesn't match the documented ABI policy
            // is worse than a build failure.
            panic!("failed to read cbindgen.toml: {error}");
        }
    };

    match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(bindings) => {
            bindings.write_to_file("include/tamga.h");
        }
        Err(error) => {
            // Warn rather than panic: a cbindgen failure here leaves the
            // committed header untouched, and CI's header-freshness gate
            // (`git diff --exit-code include/tamga.h`) is what actually
            // catches drift. Failing the build instead would make every
            // `cargo build` in the repo depend on cbindgen succeeding, which
            // is a worse trade for a header that is already committed.
            println!("cargo:warning=cbindgen failed to generate include/tamga.h: {error}");
        }
    }

    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=cbindgen.toml");
}
