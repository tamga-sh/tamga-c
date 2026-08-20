# Fuzz seed corpora

One directory per target, named after the target's suffix
(`fuzz_license_file` reads `license_file/`).

Every file here is a real artefact from `tests/fixtures/` — server-format
licence and machine files, the DER public keys, the proof payloads, and the
base64 bodies lifted out of two certificates. Nothing here was minted by a
fuzzer.

**Why seeds matter enough to commit.** Starting from an empty input, a target
has to rediscover the PEM envelope, then base64, then the certificate JSON,
then the algorithm strings, before it reaches anything interesting — and the
odds of stumbling onto `-----BEGIN LICENSE FILE-----` by mutation are nil. A
seed puts the fuzzer inside the format on the first execution, so the run is
spent on the parser's decisions rather than on its front door.

Measured on `fuzz_license_file`, 30 seconds each: from an empty corpus it
reaches `cov: 455`, from these seeds `cov: 1221`. The cold run executes some
250x more inputs to get there, which is what "spent on the front door" looks
like.

This is separate from, and does not substitute for, the harnesses being built
with instrumentation — see the comment in `../CMakeLists.txt` for what
happened when they were not.

## Running with the seeds

```sh
cmake -S . -B build-fuzz -DTAMGA_C_ENABLE_FUZZ=ON \
    -DCMAKE_C_COMPILER=$(brew --prefix llvm)/bin/clang
cmake --build build-fuzz

# Copy the seeds into a working corpus first -- libFuzzer writes new inputs
# into the first directory it is given, and this one is committed.
mkdir -p /tmp/tamga-corpus/license_file
cp tests/fuzz/corpus/license_file/* /tmp/tamga-corpus/license_file/
./build-fuzz/tests/fuzz/fuzz_license_file /tmp/tamga-corpus/license_file -max_total_time=300
```

Add a seed whenever a new format, algorithm or envelope variant appears. A
crash reproducer belongs here too, named for the fix that resolved it.
