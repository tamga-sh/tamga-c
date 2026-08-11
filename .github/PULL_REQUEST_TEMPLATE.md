## Summary

<!-- What does this PR do, and why? -->

## Checklist

- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy --all-targets -- -D warnings` passes
- [ ] `cargo test --all-targets` passes
- [ ] `ctest --test-dir build --output-on-failure` passes (if CMake config touched)
- [ ] `cargo deny check` passes
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
- [ ] If this touches `/src/license_file.rs`, `/src/machine_file.rs`, `/src/offline_proof.rs`, `/src/kdf.rs`: a `security-reviewer` pass was requested and CRITICAL/HIGH findings addressed

## Test plan

<!-- How did you verify this works? -->
