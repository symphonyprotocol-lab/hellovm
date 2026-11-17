//! Measuring a sandbox's memory without cgroups: the private memory
//! (`RssAnon` + `RssShmem` of `/proc/PID/status`) of its kernel process
//! and every process below it, each address space counted once.
//!
//! A guest thread is a host process sharing its parent's address space
//! (`clone(CLONE_VM)`), so processes are grouped by address space with
//! `kcmp(KCMP_VM)` where the host allows it; where it does not, each
//! process is counted on its own, which overestimates (the safe side for a
//! limit). `kcmp` orders address spaces, so the groups are kept sorted and
//! each process costs a binary search, not a comparison with every group:
//! the guest decides how many processes there are. A sandbox with more
//! than its limit of host processes (guest processes and threads; at most
//! [`MAX_PROCESSES`]) is reported as such and not measured: the caller
//! removes it, which makes this the sandbox's process limit too. `RssShmem` counts the guest's shared memory, but also the
//! template's snapshot pages a clone has touched without writing them (they
//! are shared with every other clone): that overestimates by at most the
//! snapshot's size per address space.

use std::collections::{HashMap, HashSet};

/// Most processes looked at per scan.
const MAX_PIDS: usize = 1 << 17;

pub use crate::config::MAX_PROCESSES;

/// What one sandbox uses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    /// Private memory in bytes.
    pub bytes: u64,
    /// Host processes found (at most the limit plus one).
    pub processes: usize,
    /// More processes than the limit: `bytes` is not complete.
    pub too_many: bool,
}

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

/// How the address spaces of `a` and `b` compare in the host's order,
/// `None` when the host does not say (no `kcmp`, a process that ended).
fn compare_vm(a: u32, b: u32) -> Option<std::cmp::Ordering> {
    const KCMP_VM: libc::c_long = 1;
    // SAFETY: plain syscall with integer arguments.
    let ret = unsafe { libc::syscall(libc::SYS_kcmp, a, b, KCMP_VM, 0, 0) };
    match ret {
        0 => Some(std::cmp::Ordering::Equal),
        1 => Some(std::cmp::Ordering::Less),
        2 => Some(std::cmp::Ordering::Greater),
        _ => None,
    }
}

/// Whether `pid` shares its address space with one of `spaces` (one
/// process per address space, in the host's order); if not and the host
/// can order it, it is added. `None`: the host does not say.
fn known_space(spaces: &mut Vec<u32>, pid: u32) -> Option<bool> {
    let (mut low, mut high) = (0, spaces.len());
    while low < high {
        let mid = (low + high) / 2;
        match compare_vm(pid, spaces[mid])? {
            std::cmp::Ordering::Equal => return Some(true),
            std::cmp::Ordering::Less => high = mid,
            std::cmp::Ordering::Greater => low = mid + 1,
        }
    }
    spaces.insert(low, pid);
    Some(false)
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

/// The private memory and process count of each root's process tree;
/// each root comes with its process limit.
pub fn measure(roots: &[(u32, usize)]) -> HashMap<u32, Usage> {
    let tree = children();
    let mut out = HashMap::new();
    for &(root, max_processes) in roots {
        let max_processes = max_processes.min(MAX_PROCESSES);
        let mut seen = HashSet::new();
        let mut stack = vec![root];
        let mut members = Vec::new();
        let mut too_many = false;
        while let Some(pid) = stack.pop() {
            if !seen.insert(pid) {
                continue;
            }
            if members.len() > max_processes {
                too_many = true;
                break;
            }
            members.push(pid);
            if let Some(kids) = tree.get(&pid) {
                stack.extend(kids);
            }
        }
        let mut usage = Usage {
            bytes: 0,
            processes: members.len(),
            too_many,
        };
        if !too_many {
            // One process per address space.
            let mut spaces: Vec<u32> = Vec::new();
            for pid in members {
                if known_space(&mut spaces, pid) == Some(true) {
                    continue;
                }
                usage.bytes += private_bytes(pid).unwrap_or(0);
            }
        }
        out.insert(root, usage);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measures_this_process_and_its_threads_once() {
        let me = std::process::id();
        let before = measure(&[(me, MAX_PROCESSES)])[&me].bytes;
        assert!(before > 0);
        // A thread shares the address space: no extra count (threads are
        // not separate /proc entries anyway).
        let block = vec![1u8; 64 << 20];
        std::hint::black_box(&block);
        let after = measure(&[(me, MAX_PROCESSES)])[&me].bytes;
        assert!(after >= before + (60 << 20), "{before} -> {after}");
        let child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap();
        // The child belongs to this process's tree and has memory of its
        // own. (Not compared with the total above: other tests of this
        // process start and end children meanwhile.)
        assert!(children()[&me].contains(&child.id()));
        let alone = measure(&[(child.id(), MAX_PROCESSES)])[&child.id()];
        assert!(alone.bytes > 0 && alone.processes == 1, "{alone:?}");
        let mut child = child;
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(ppid_of(me), Some(unsafe { libc::getppid() } as u32));
    }

    #[test]
    fn address_spaces_are_grouped_and_processes_counted() {
        let me = std::process::id();
        // Children with their own address spaces.
        let mut kids: Vec<_> = (0..5)
            .map(|_| {
                std::process::Command::new("sleep")
                    .arg("30")
                    .spawn()
                    .unwrap()
            })
            .collect();
        let usage = measure(&[(me, MAX_PROCESSES)])[&me];
        assert!(usage.processes >= 6, "{usage:?}");
        assert!(!usage.too_many);
        assert!(
            measure(&[(me, 3)])[&me].too_many,
            "six processes, limit three"
        );
        let mut spaces = Vec::new();
        let pids: Vec<u32> = std::iter::once(me)
            .chain(kids.iter().map(|k| k.id()))
            .collect();
        match compare_vm(me, me) {
            // The host lets us compare: each process is new once, known
            // the second time, and the list stays one per address space.
            Some(_) => {
                for &pid in &pids {
                    assert_eq!(known_space(&mut spaces, pid), Some(false));
                }
                for &pid in &pids {
                    assert_eq!(known_space(&mut spaces, pid), Some(true));
                }
                assert_eq!(spaces.len(), pids.len());
            }
            None => eprintln!("note: kcmp is refused here; address spaces are not grouped"),
        }
        for kid in &mut kids {
            let _ = kid.kill();
            let _ = kid.wait();
        }
    }
}
