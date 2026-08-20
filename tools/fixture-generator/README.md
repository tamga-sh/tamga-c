# Fixture generator

A development-only tool. **It is not part of the library, not referenced by
CMake, and not needed to build, test or use this SDK.** Nothing in `src/`,
`tests/` or CI touches it, and the library itself has no dependencies at all.

It exists to produce `tests/fixtures/offline/` -- real `.lic`, `.mach` and
offline-proof files in the server's format -- and, critically, to run each one
through `tamga-rust`'s verifier before writing it out. Fixtures generated and
checked by the same implementation prove only self-consistency; these are
meant to be evidence of interoperability, which requires a second
implementation to agree.

That second implementation is written in Rust, which is why this directory is.
It needs a checkout of `tamga-rust` as a sibling of this repository.

```sh
cargo run
```

The generator fails rather than writing anything if `tamga-rust` disagrees
with the expected verdict for any fixture -- including the deliberately broken
ones, which it asserts are rejected.

See `tests/fixtures/offline/README.md` for what each generated file is for.
