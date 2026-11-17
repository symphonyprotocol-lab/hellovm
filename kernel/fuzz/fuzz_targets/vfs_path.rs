#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| hellovm_fuzz::vfs_path(data));
