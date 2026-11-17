//! Measuring a sandbox's memory without cgroups: the private memory
//! (`RssAnon` + `RssShmem` of `/proc/PID/status`) of its kernel process
//! and every process below it, each address space counted once.
//!
//! A guest thread is a host process sharing its parent's address space
//! (`clone(CLONE_VM)`), so processes are grouped by address space with
//! `kcmp(KCMP_VM)` where the host allows it; where it does not, each
//! process is counted on its own, which overestimates (the safe side for a
//! limit). `RssShmem` counts the guest's shared memory, but also the
//! template's snapshot pages a clone has touched without writing them (they
//! are shared with every other clone): that overestimates by at most the
//! snapshot's size per address space.

use std::collections::{HashMap, HashSet};

/// Most processes looked at per scan.
const MAX_PIDS: usize = 1 << 17;

fn ppid_of(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // `pid (comm) state ppid ...`; comm may hold spaces and parentheses.
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

fn private_bytes(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let mut kib = 0u64;
    let mut found = false;
    for line in status.lines() {
        for key in ["RssAnon:", "RssShmem:"] {
            if let Some(value) = line.strip_prefix(key) {
                let number = value.trim().trim_end_matches("kB").trim();
                kib += number.parse::<u64>().ok()?;
                found = true;
            }
        }
    }
    found.then_some(kib * 1024)
}

/// Whether `a` and `b` share an address space: `Some(true)`/`Some(false)`,
/// `None` when the host does not say.
fn same_vm(a: u32, b: u32) -> Option<bool> {
    const KCMP_VM: libc::c_long = 1;
    // SAFETY: plain syscall with integer arguments.
    let ret = unsafe { libc::syscall(libc::SYS_kcmp, a, b, KCMP_VM, 0, 0) };
    match ret {
        0 => Some(true),
        1..=3 => Some(false),
        _ => None,
    }
}

/// The process tree of the host, from `/proc`: children by parent.
fn children() -> HashMap<u32, Vec<u32>> {
    let mut tree: HashMap<u32, Vec<u32>> = HashMap::new();
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return tree;
    };
    for entry in dir.flatten().take(MAX_PIDS) {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if let Some(ppid) = ppid_of(pid) {
            tree.entry(ppid).or_default().push(pid);
        }
    }
    tree
}

/// The private memory of each root's process tree, in bytes.
pub fn measure(roots: &[u32]) -> HashMap<u32, u64> {
    let tree = children();
    let mut out = HashMap::new();
    for &root in roots {
        let mut seen = HashSet::new();
        let mut stack = vec![root];
        let mut members = Vec::new();
        while let Some(pid) = stack.pop() {
            if !seen.insert(pid) || seen.len() > 4096 {
                continue;
            }
            members.push(pid);
            if let Some(kids) = tree.get(&pid) {
                stack.extend(kids);
            }
        }
        // One representative per address space.
        let mut spaces: Vec<u32> = Vec::new();
        let mut total = 0u64;
        for pid in members {
            let shared = spaces.iter().any(|&rep| same_vm(rep, pid) == Some(true));
            if shared {
                continue;
            }
            if let Some(bytes) = private_bytes(pid) {
                total += bytes;
                spaces.push(pid);
            }
        }
        out.insert(root, total);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measures_this_process_and_its_threads_once() {
        let me = std::process::id();
        let before = measure(&[me])[&me];
        assert!(before > 0);
        // A thread shares the address space: no extra count (threads are
        // not separate /proc entries anyway).
        let block = vec![1u8; 64 << 20];
        std::hint::black_box(&block);
        let after = measure(&[me])[&me];
        assert!(after >= before + (60 << 20), "{before} -> {after}");
        let child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let with_child = measure(&[me])[&me];
        assert!(with_child >= after, "{after} -> {with_child}");
        let mut child = child;
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(ppid_of(me), Some(unsafe { libc::getppid() } as u32));
    }
}
