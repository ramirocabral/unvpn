#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| unvpn::fuzz::tunnel_config(data));
