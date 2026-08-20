## Summary

<!-- What does this PR do, and why? -->

## Checklist

- [ ] `clang-format --dry-run --Werror` passes over `src/ include/ tests/ examples/`
- [ ] `clang-tidy -p build` passes over the sources in the compilation database
- [ ] `ctest --test-dir build --output-on-failure` passes
- [ ] `ctest --test-dir build-asan` passes (configured with `-DTAMGA_C_ENABLE_ASAN=ON`)
- [ ] The `-DTAMGA_HTTP=none` build still passes and still links against libc alone
- [ ] Coverage is at or above 80% (`sh Scripts/check-coverage.sh 80 build-cov`)
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/) —
      release-please reads them, and a stray `!` forces a major release

## If this touches the public header

- [ ] No existing signature changed and no enum value was renumbered
- [ ] `tests/c/` still passes **unmodified** — it is the v1.2.2 harness and the
      only real proof the ABI held
- [ ] New enum values are appended, never interleaved

## If this touches `src/crypto/`, `src/checkout/`, `src/proof.c` or `src/http/`

- [ ] A `security-reviewer` pass was requested for **each** area separately, and
      every CRITICAL and HIGH finding is addressed
- [ ] Any new protocol behaviour has a **negative** test, not only a positive one
- [ ] The fuzz targets still run clean (`-DTAMGA_C_ENABLE_FUZZ=ON`, clang),
      started from `tests/fuzz/corpus/` — copy it aside first, libFuzzer
      writes into the directory it is given

## Test plan

<!-- How did you verify this works? Name the commands you actually ran. -->
