# Fuzzing

libFuzzer targets for the parsers that read gateway data, which the engine
runs as root (`unvpn::fuzz`): `http`, `ppp`, `ikev1`, `ikev2`, `ccc`, `der`,
`xml` and `tunnel_config`. `seeds/` holds a few valid inputs for each.

With [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) on nightly, from
the repository root:

```sh
cargo +nightly fuzz run xml fuzz/corpus/xml fuzz/seeds/xml
```

On stable, the same coverage instrumentation without a sanitizer:

```sh
cd fuzz
RUSTFLAGS="--cfg fuzzing -Cpasses=sancov-module \
  -Cllvm-args=-sanitizer-coverage-level=4 \
  -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
  -Cllvm-args=-sanitizer-coverage-pc-table \
  -Cllvm-args=-sanitizer-coverage-trace-compares \
  -Cdebug-assertions -Coverflow-checks" \
  cargo build --release --target x86_64-unknown-linux-gnu --bins
mkdir -p corpus/xml
./target/x86_64-unknown-linux-gnu/release/xml corpus/xml seeds/xml -max_total_time=300
```

`cargo test -p unvpn` also runs every entry point over mutated seeds, as a
quick check that needs no fuzzer.
