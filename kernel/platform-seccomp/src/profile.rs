//! Facts about the kernel process that stay fixed for its lifetime, taken
//! once, before it confines itself (`hellovm-sandbox`).
//!
//! * The stub executable lives in one sealed memfd per host process, made
//!   on first use. Every app process `execveat`s that same fd, so the
//!   kernel process never needs `memfd_create` once it runs guest code, and
//!   its own seccomp filter can pin `execveat` to that one fd number.
//! * The kernel process's executable mappings (its binary, the C library,
//!   the dynamic linker and the vDSO), read from `/proc/self/maps`. The
//!   kernel process's filter judges a syscall by whether it was made from
//!   inside one of them (see `hellovm-sandbox`), so the platform keeps
//!   every app address space out of these ranges: app code can never run
//!   at an address the filter would take for the kernel's own code.
//! * The top of the user address space, so that a new app process can be
//!   emptied with two `munmap`s without reading its `/proc/<pid>/maps`.
//!
//! Nothing here is read again later: a confined kernel process cannot open
//! `/proc`, and does not need to.

use std::io;
use std::ops::Range;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::OnceLock;

use hellovm_core::Arch;

use crate::stub;
use crate::sys;

/// See the module documentation.
#[derive(Debug)]
pub struct HostProfile {
    stub: OwnedFd,
    code: Vec<Range<u64>>,
    task_size: u64,
}

static PROFILE: OnceLock<Result<HostProfile, String>> = OnceLock::new();

/// The process-wide [`HostProfile`], computed on the first call. Call it
/// before the process confines itself.
pub fn host_profile() -> io::Result<&'static HostProfile> {
    PROFILE
        .get_or_init(|| HostProfile::take().map_err(|err| err.to_string()))
        .as_ref()
        .map_err(|err| io::Error::other(err.clone()))
}

impl HostProfile {
    fn take() -> io::Result<HostProfile> {
        let arch = Arch::native().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, "unsupported host architecture")
        })?;
        let stub = sys::sealed_memfd(c"hellovm-stub", &stub::elf(arch))
            .map_err(|err| io::Error::new(err.kind(), format!("creating the stub memfd: {err}")))?;
        let maps = std::fs::read_to_string("/proc/self/maps")
            .map_err(|err| io::Error::new(err.kind(), format!("reading /proc/self/maps: {err}")))?;
        let (code, highest) = parse_maps(&maps)?;
        let local = 0u8;
        let task_size = task_size(highest.max(&local as *const u8 as u64));
        Ok(HostProfile {
            stub,
            code,
            task_size,
        })
    }

    /// The stub memfd every app process executes.
    pub fn stub_fd(&self) -> RawFd {
        self.stub.as_raw_fd()
    }

    /// The kernel process's executable mappings, page-aligned, sorted.
    pub fn code_ranges(&self) -> &[Range<u64>] {
        &self.code
    }

    /// One past the highest address the host can map for a process.
    pub fn task_size(&self) -> u64 {
        self.task_size
    }

    /// The highest address the core may use in an app address space:
    /// below every kernel code range in the topmost 64 GiB (where the host
    /// puts the stack and, on some kernels, the vDSO), so that the app's
    /// stack never lands on one.
    pub fn app_max_addr(&self, page_size: u64) -> u64 {
        const TOP_ZONE: u64 = 64 << 30;
        let zone = self.task_size.saturating_sub(TOP_ZONE);
        self.code
            .iter()
            .filter(|r| r.start >= zone)
            .map(|r| r.start)
            .min()
            .unwrap_or(self.task_size)
            & !(page_size - 1)
    }
}

/// The executable mappings in a `/proc/<pid>/maps` text, and the highest
/// end address of any mapping (the x86_64 vsyscall page aside, which is
/// above the user range).
fn parse_maps(maps: &str) -> io::Result<(Vec<Range<u64>>, u64)> {
    let mut code: Vec<Range<u64>> = Vec::new();
    let mut highest = 0;
    for line in maps.lines() {
        if line.ends_with("[vsyscall]") {
            continue;
        }
        let mut fields = line.split_whitespace();
        let range = fields.next().unwrap_or("");
        let perms = fields.next().unwrap_or("");
        let parse = |s: Option<&str>| s.and_then(|s| u64::from_str_radix(s, 16).ok());
        let mut bounds = range.split('-');
        let (Some(start), Some(end)) = (parse(bounds.next()), parse(bounds.next())) else {
            return Err(io::Error::other(format!("bad maps line {line:?}")));
        };
        highest = highest.max(end);
        if perms.as_bytes().get(2) == Some(&b'x') {
            match code.last_mut() {
                Some(last) if last.end == start => last.end = end,
                _ => code.push(start..end),
            }
        }
    }
    if code.is_empty() {
        return Err(io::Error::other("no executable mapping in /proc/self/maps"));
    }
    Ok((code, highest))
}

/// The size of the user address space, from an address near its top.
fn task_size(probe: u64) -> u64 {
    if cfg!(target_arch = "x86_64") {
        // 47-bit user space (also the default window with 5-level paging),
        // minus the guard page below the non-canonical hole.
        (1 << 47) - 0x1000
    } else {
        // aarch64: 39, 42, 47 or 48 bits (52-bit kernels default to a 48-bit
        // window). The stack is near the top.
        probe.checked_next_power_of_two().unwrap_or(1 << 48)
    }
}

/// The two ranges that hold everything a fresh app process has besides
/// the stub: below it and above it, up to the top of the user range.
pub fn outside_stub(page_size: u64, task_size: u64) -> [(u64, u64); 2] {
    let stub_end = stub::STUB_BASE + stub::STUB_RESERVED;
    [
        (page_size, stub::STUB_BASE - page_size),
        (stub_end, task_size - stub_end),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_maps_and_merges_adjacent_code() {
        let maps = "\
5555000000-5555001000 r--p 00000000 00:1 1 /bin/x
5555001000-5555003000 r-xp 00001000 00:1 1 /bin/x
5555003000-5555004000 r-xp 00003000 00:1 1 /bin/x
7fff00000000-7fff00021000 rw-p 00000000 00:00 0 [stack]
7fff00030000-7fff00032000 r-xp 00000000 00:00 0 [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0 [vsyscall]
";
        let (code, highest) = parse_maps(maps).unwrap();
        assert_eq!(
            code,
            vec![0x5555001000..0x5555004000, 0x7fff00030000..0x7fff00032000]
        );
        assert_eq!(highest, 0x7fff00032000);
    }

    #[test]
    fn own_profile_is_sane() {
        let profile = host_profile().unwrap();
        assert!(profile.stub_fd() > 2);
        let here = own_profile_is_sane as *const () as usize as u64;
        assert!(profile.code_ranges().iter().any(|r| r.contains(&here)));
        let max = profile.app_max_addr(sys::page_size());
        assert!(max > stub::STUB_BASE + stub::STUB_RESERVED && max <= profile.task_size());
    }
}
