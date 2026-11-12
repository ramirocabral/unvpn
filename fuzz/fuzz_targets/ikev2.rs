#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| unvpn::fuzz::ikev2(data));
