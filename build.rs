//! Regenerates `include/tamga.h` from this crate's `extern "C"` API via
//! cbindgen on every build.
//!
//! The committed `include/tamga.h` is a placeholder until `src/lib.rs` has
//! real exports (see that file's module docs and
//! docs/plans/tamga-c.plan.md Section B). CI's header-freshness gate
//! (`.github/workflows/ci.yml`) runs a build and then `git diff --exit-code
//! include/tamga.h` — a drifted/uncommitted header fails CI.

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
            // Non-fatal during scaffolding: src/lib.rs's `extern "C"` fns
            // are still `todo!()` stubs with signatures that may not be
            // fully cbindgen-clean yet (Sections C/D/E aren't implemented).
            // Warn instead of panicking so `cargo build` stays usable while
            // the ABI is still being designed; tighten this to a hard
            // failure once Section B's header freeze is real.
            println!("cargo:warning=cbindgen failed to generate include/tamga.h: {error}");
        }
    }

    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=cbindgen.toml");
}
