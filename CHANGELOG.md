# Changelog

## [1.3.0](https://github.com/tamga-sh/tamga-c/compare/v1.2.2...v1.3.0) (2026-08-20)


### Features

* rewrite as a native C11 library with the full HTTP surface ([#27](https://github.com/tamga-sh/tamga-c/issues/27)) ([7cd4f4e](https://github.com/tamga-sh/tamga-c/commit/7cd4f4e4bbebd11ffda67d359e427b73ce9635dc))

## [1.2.2](https://github.com/tamga-sh/tamga-c/compare/v1.2.1...v1.2.2) (2026-08-18)


### Bug Fixes

* open release PRs with a GitHub App token and make the vcpkg port installable ([#22](https://github.com/tamga-sh/tamga-c/issues/22)) ([9c24f16](https://github.com/tamga-sh/tamga-c/commit/9c24f168357d30ff176dc551b4aead25a31fba57))

## [1.2.1](https://github.com/tamga-sh/tamga-c/compare/v1.2.0...v1.2.1) (2026-08-18)


### Bug Fixes

* actually install the compiled library, not just the header ([97d8790](https://github.com/tamga-sh/tamga-c/commit/97d879085f4db8e714ee33e931d7e3c6baf258f4))
* correct SDK documentation and align package metadata ([22389f5](https://github.com/tamga-sh/tamga-c/commit/22389f5423196621eaa94dc24ca05b5e34979bb2))

## [1.2.0](https://github.com/tamga-sh/tamga-c/compare/v1.1.1...v1.2.0) (2026-08-13)


### Features

* license-file HKDF + offline format v2 (via tamga-rust delegation) ([fd79a8a](https://github.com/tamga-sh/tamga-c/commit/fd79a8a4e8394b6ea0daff463d6c930efb884b16))

## [1.1.1](https://github.com/tamga-sh/tamga-c/compare/v1.1.0...v1.1.1) (2026-08-12)


### Bug Fixes

* return a length-specific error code instead of NULL_ARGUMENT ([f3aaca9](https://github.com/tamga-sh/tamga-c/commit/f3aaca97904014ebc4190251a6099119cc158a26))
* return a length-specific error code instead of NULL_ARGUMENT ([dd1def8](https://github.com/tamga-sh/tamga-c/commit/dd1def8588a661bf42f42139e7626a76976ad376))

## [1.1.0](https://github.com/tamga-sh/tamga-c/compare/v1.0.1...v1.1.0) (2026-08-12)


### Features

* **ci:** add iOS device + simulator targets to build-native.yml ([50fe00c](https://github.com/tamga-sh/tamga-c/commit/50fe00c7ce8e27781a0191d51b08428e948bff1b))


### Bug Fixes

* **ci:** build ios-arm64 as staticlib-only ([4ef359b](https://github.com/tamga-sh/tamga-c/commit/4ef359b76d230520406335125c52d9a138cc29cc))
* **ci:** pin build-native.yml's checkout to tamga-c explicitly ([885a9ce](https://github.com/tamga-sh/tamga-c/commit/885a9ce25d3f58c11c0df3312d4cda0429b1eff5))

## [1.0.1](https://github.com/tamga-sh/tamga-c/compare/v1.0.0...v1.0.1) (2026-08-11)


### Bug Fixes

* **ci:** explicitly grant contents:write to package-and-attach ([8bb89bd](https://github.com/tamga-sh/tamga-c/commit/8bb89bdbcf7d5a32fcca55743c22164a782e3195))

## 1.0.0 (2026-08-11)


### Features

* implement C test harness and working examples (Sections C-H) ([0bad927](https://github.com/tamga-sh/tamga-c/commit/0bad92720c01a33aac2a9ca855848d602af29e68))
* implement license-file checkout FFI (Section C) ([34d1f65](https://github.com/tamga-sh/tamga-c/commit/34d1f654042806983d844eedd7e6a7ad056d1dd6))
* implement machine-file checkout FFI (Section D) ([2277a7e](https://github.com/tamga-sh/tamga-c/commit/2277a7e7a1e00635a99cb8846cd6df2cdedfe7f2))
* implement offline-proof verify FFI (Section E, partial) ([864d01c](https://github.com/tamga-sh/tamga-c/commit/864d01c1e4cbd34fb95c6dddebdb36461cb94be4))
* implement Section F (memory/lifecycle) + security-reviewer fixes ([992ebcd](https://github.com/tamga-sh/tamga-c/commit/992ebcdb0c316179ca83a2a12cc0a56416733aa1))


### Bug Fixes

* **ci:** allow Unicode-3.0, CDLA-Permissive-2.0, and MPL-2.0 licenses ([e1848c6](https://github.com/tamga-sh/tamga-c/commit/e1848c68f4f9a1cd1062df192ae467fb9ef8ccb3))
* **ci:** depend on tamga-rust via crates.io instead of a local path ([9d606cb](https://github.com/tamga-sh/tamga-c/commit/9d606cb44834404b99a73576d05e18b10d05c40b))
* **ci:** link Windows system libraries into the C test harness ([124b981](https://github.com/tamga-sh/tamga-c/commit/124b9819eb0b5fe324b6629bf05564fbf9ce623e))

## Changelog

All notable changes to this project are documented in this file.

This file is maintained automatically by
[release-please](https://github.com/googleapis/release-please) once the
first release lands — see `.github/workflows/release.yml`. Entries below
this point are generated from Conventional Commits history; do not hand-edit
them once release-please starts managing this file.
