//! Tests of the KVM platform that need its internals: the shared
//! platform's tests that need a VM (`hellovm_platform_arm64::testing`).

use std::sync::Mutex;

use hellovm_platform_arm64::testing;

use crate::{KvmConfig, KvmPlatform};

/// The tests that make a VM take turns (the host may have few CPUs).
pub(crate) static VM: Mutex<()> = Mutex::new(());

pub(crate) fn make(config: KvmConfig) -> Option<KvmPlatform> {
    match KvmPlatform::new(config) {
        Ok(p) => Some(p),
        Err(err) if std::env::var("HELLOVM_REQUIRE_E2E").as_deref() == Ok("1") => {
            panic!("HELLOVM_REQUIRE_E2E=1 but the KVM platform is unavailable: {err}")
        }
        Err(err) => {
            eprintln!("SKIPPING: the KVM platform is unavailable: {err}");
            None
        }
    }
}

#[test]
fn registers_read_before_the_task_runs_again_have_the_result() {
    let _guard = VM.lock().unwrap_or_else(|e| e.into_inner());
    testing::registers_read_before_the_task_runs_again_have_the_result(make);
}

#[test]
fn spaces_beyond_the_asids_share_one_and_flush() {
    let _guard = VM.lock().unwrap_or_else(|e| e.into_inner());
    testing::spaces_beyond_the_asids_share_one_and_flush(make);
}

#[test]
fn a_slice_that_ends_in_a_vector_still_ends() {
    let _guard = VM.lock().unwrap_or_else(|e| e.into_inner());
    testing::a_slice_that_ends_in_a_vector_still_ends(make);
}
