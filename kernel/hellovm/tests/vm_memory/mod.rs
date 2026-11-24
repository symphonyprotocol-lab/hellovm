//! What the command-line tests of the VM platforms (HVF, KVM) share: a
//! program that frees memory and uses new memory, and the check that the
//! kernel process's memory follows.

#![allow(dead_code)]

/// Python for [`memory_goes_back`]: at each line it prints, it waits for
/// one on stdin. It touches 256 MiB, frees it, then reads 256 MiB of new
/// memory, which must be zero, and frees that; then 50 processes that
/// each touch and free 8 MiB.
pub const FREE_AND_REUSE: &str = r#"
import os, sys
def step(s):
    print(s, flush=True)
    sys.stdin.readline()
step("start")
b = b"\x01" * (256 << 20)
step("touched")
del b
step("freed")
c = bytearray(256 << 20)
print("zero", c.count(0) == len(c), flush=True)
sys.stdin.readline()
del c
for _ in range(50):
    pid = os.fork()
    if pid == 0:
        x = b"\x02" * (8 << 20)
        os._exit(0 if x[-1] == 2 else 1)
    assert os.waitpid(pid, 0)[1] == 0
step("forked")
"#;

/// Drives [`FREE_AND_REUSE`] in the kernel process `pid` (`line` reads
/// its next line, `send` answers it) and checks that its footprint
/// (`footprint`: on macOS its physical footprint, on Linux its resident
/// size) follows: up by 256 MiB, back to near the start once freed and once the
/// 50 processes are done, and the new memory zero. Returns the footprints
/// at start, touched, freed and at the end, in MiB.
pub fn memory_goes_back(
    footprint: impl Fn() -> u64,
    pid: u32,
    mut line: impl FnMut() -> String,
    mut send: impl FnMut(),
) -> [f64; 4] {
    const MIB: f64 = 1024.0 * 1024.0;
    // Some slack over the start: the pools keep up to 4 MiB of free app
    // memory and 1 MiB of tables until the sandbox is idle for 20 ms, and
    // the kernel's own heap and the guest's page cache move a little.
    const SLACK: u64 = 24 << 20;
    let settled = |limit: u64| {
        let start = std::time::Instant::now();
        loop {
            let now = footprint();
            if now <= limit || start.elapsed() > std::time::Duration::from_secs(5) {
                // Then what it settles at (the reserve goes once idle).
                std::thread::sleep(std::time::Duration::from_millis(200));
                return footprint().min(now);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    };
    assert_eq!(line(), "start\n");
    std::thread::sleep(std::time::Duration::from_millis(100));
    let start = footprint();
    assert!(start > 0, "no footprint for {pid}");
    send();
    assert_eq!(line(), "touched\n");
    let touched = footprint();
    assert!(
        touched > start + (250 << 20),
        "touched: {touched} from {start}"
    );
    send();
    assert_eq!(line(), "freed\n");
    let freed = settled(start + SLACK);
    assert!(freed <= start + SLACK, "freed: {freed}, start {start}");
    send();
    assert_eq!(
        line(),
        "zero True\n",
        "memory handed out again was not zero"
    );
    send();
    assert_eq!(line(), "forked\n");
    let end = settled(start + SLACK);
    assert!(
        end <= start + SLACK,
        "after the forks: {end}, start {start}"
    );
    send();
    [start, touched, freed, end].map(|b| b as f64 / MIB)
}
