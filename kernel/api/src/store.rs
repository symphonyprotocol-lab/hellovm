//! Sandbox metadata: which sandbox belongs to which tenant and runs on
//! which node.
//!
//! The nodes are the source of truth for what runs (each node knows the
//! tenant of every sandbox it runs and removes them itself when they end),
//! so this store is rebuilt from them: at start-up, and then every
//! `reconcile_interval` ([`Store::replace_node`]). [`MemoryStore`] keeps it
//! in this process. A Postgres store implements the same trait later: rows
//! written on create and delete, reservations as rows counted in the same
//! transaction, and reconciliation updating them from the nodes; the API
//! then no longer needs every node's answer to know a tenant's count.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Instant;

use hellovm_control::ids::SandboxId;

/// One sandbox the API knows of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub id: SandboxId,
    pub tenant: String,
    pub node: String,
    pub template: String,
    /// Its memory limit, in bytes (counted against the tenant's
    /// `max_memory_mb`).
    pub memory_limit: u64,
}

/// A slot of a tenant's sandbox limit (and memory) held for a creation in
/// progress.
pub struct Reservation<'a> {
    store: &'a dyn Store,
    tenant: String,
    memory: u64,
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        self.store.release(&self.tenant, self.memory);
    }
}

/// Why a reservation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The tenant has `max_sandboxes` already.
    Count,
    /// Its sandboxes' memory limits and this one's would be over its
    /// `max_memory_mb`.
    Memory,
}

/// Deletes of sandboxes on unreachable nodes kept at once, per node.
pub const MAX_DELETES_PER_NODE: usize = 4096;

pub trait Store: Send + Sync {
    /// Holds one of `tenant`'s `max` slots and `memory` bytes of its
    /// `max_memory`, or refuses when the slots are all taken by sandboxes
    /// and creations in progress, or the memory limits of those and this
    /// one would be over `max_memory`. Both are checked under one lock.
    fn reserve(
        &self,
        tenant: &str,
        max: usize,
        memory: u64,
        max_memory: Option<u64>,
    ) -> Result<Reservation<'_>, Refused>;
    /// Gives a slot back (by dropping its [`Reservation`]).
    fn release(&self, tenant: &str, memory: u64);
    fn insert(&self, record: Record);
    fn get(&self, id: &SandboxId) -> Option<Record>;
    /// Forgets a sandbox that ended; it stays among the ended ones.
    fn remove(&self, id: &SandboxId) -> Option<Record>;
    /// Forgets a sandbox its tenant deleted: nobody needs telling why it
    /// is gone.
    fn forget(&self, id: &SandboxId);
    /// A sandbox that ended not long ago ([`ENDED`] are remembered): its
    /// node can still say why.
    fn ended(&self, id: &SandboxId) -> Option<Record>;
    fn of_tenant(&self, tenant: &str) -> Vec<Record>;
    /// Makes the records of `node` what it reported at `asked` (records
    /// inserted after that are kept: the node's list predates them).
    /// Sandboxes with a delete to do are left out.
    fn replace_node(&self, node: &str, asked: Instant, records: Vec<Record>);
    /// Its tenant deleted a sandbox whose node does not answer: it no
    /// longer counts or is listed, and is deleted on the node later.
    /// `None` when there is no such sandbox, or too many deletes wait on
    /// its node already.
    fn delete_later(&self, id: &SandboxId) -> Option<Record>;
    /// Every delete still to do.
    fn deletes(&self) -> Vec<Record>;
    /// A delete to do, read back from the usage log at start-up.
    fn add_delete(&self, record: Record);
    /// A delete was done, or is not needed any more.
    fn delete_done(&self, id: &SandboxId);
    /// A tenant's sandboxes (and creations in progress) and the sum of
    /// their memory limits.
    fn held(&self, tenant: &str) -> (usize, u64);
}

/// Ended sandboxes remembered.
pub const ENDED: usize = 4096;

#[derive(Default)]
struct Inner {
    records: HashMap<SandboxId, (Record, Instant)>,
    /// Creations in progress per tenant: how many, and their memory.
    pending: HashMap<String, (usize, u64)>,
    /// Oldest first.
    ended: VecDeque<Record>,
    /// Deletes to do on nodes that did not answer.
    deletes: HashMap<SandboxId, Record>,
}

impl Inner {
    fn held(&self, tenant: &str) -> (usize, u64) {
        let (mut n, mut memory) = self.pending.get(tenant).copied().unwrap_or((0, 0));
        for (r, _) in self.records.values().filter(|(r, _)| r.tenant == tenant) {
            n += 1;
            memory = memory.saturating_add(r.memory_limit);
        }
        (n, memory)
    }
}

impl Inner {
    fn end(&mut self, record: Record) {
        if self.ended.len() >= ENDED {
            self.ended.pop_front();
        }
        self.ended.push_back(record);
    }
}

/// The store in this process's memory.
#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
}

impl MemoryStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Store for MemoryStore {
    fn reserve(
        &self,
        tenant: &str,
        max: usize,
        memory: u64,
        max_memory: Option<u64>,
    ) -> Result<Reservation<'_>, Refused> {
        let mut inner = self.lock();
        let (have, held) = inner.held(tenant);
        if have >= max {
            return Err(Refused::Count);
        }
        if max_memory.is_some_and(|max| held.saturating_add(memory) > max) {
            return Err(Refused::Memory);
        }
        let entry = inner.pending.entry(tenant.to_string()).or_default();
        entry.0 += 1;
        entry.1 = entry.1.saturating_add(memory);
        Ok(Reservation {
            store: self,
            tenant: tenant.to_string(),
            memory,
        })
    }

    fn release(&self, tenant: &str, memory: u64) {
        let mut inner = self.lock();
        if let Some((n, m)) = inner.pending.get_mut(tenant) {
            *n = n.saturating_sub(1);
            *m = m.saturating_sub(memory);
            if *n == 0 {
                inner.pending.remove(tenant);
            }
        }
    }

    fn insert(&self, record: Record) {
        self.lock()
            .records
            .insert(record.id, (record, Instant::now()));
    }

    fn get(&self, id: &SandboxId) -> Option<Record> {
        self.lock().records.get(id).map(|(r, _)| r.clone())
    }

    fn remove(&self, id: &SandboxId) -> Option<Record> {
        let mut inner = self.lock();
        let (record, _) = inner.records.remove(id)?;
        inner.end(record.clone());
        Some(record)
    }

    fn forget(&self, id: &SandboxId) {
        self.lock().records.remove(id);
    }

    fn ended(&self, id: &SandboxId) -> Option<Record> {
        self.lock()
            .ended
            .iter()
            .rev()
            .find(|r| r.id == *id)
            .cloned()
    }

    fn of_tenant(&self, tenant: &str) -> Vec<Record> {
        self.lock()
            .records
            .values()
            .filter(|(r, _)| r.tenant == tenant)
            .map(|(r, _)| r.clone())
            .collect()
    }

    fn replace_node(&self, node: &str, asked: Instant, records: Vec<Record>) {
        let mut inner = self.lock();
        let reported: std::collections::HashSet<SandboxId> = records.iter().map(|r| r.id).collect();
        let gone: Vec<SandboxId> = inner
            .records
            .iter()
            .filter(|(id, (r, inserted))| {
                r.node == node && *inserted <= asked && !reported.contains(id)
            })
            .map(|(id, _)| *id)
            .collect();
        for id in gone {
            if let Some((record, _)) = inner.records.remove(&id) {
                inner.end(record);
            }
        }
        for record in records.into_iter().filter(|r| r.node == node) {
            if inner.deletes.contains_key(&record.id) {
                continue;
            }
            inner.records.entry(record.id).or_insert((record, asked));
        }
    }

    fn delete_later(&self, id: &SandboxId) -> Option<Record> {
        let mut inner = self.lock();
        let node = inner.records.get(id)?.0.node.clone();
        let waiting = inner.deletes.values().filter(|r| r.node == node).count();
        if waiting >= MAX_DELETES_PER_NODE {
            return None;
        }
        let (record, _) = inner.records.remove(id)?;
        inner.deletes.insert(*id, record.clone());
        Some(record)
    }

    fn deletes(&self) -> Vec<Record> {
        self.lock().deletes.values().cloned().collect()
    }

    fn add_delete(&self, record: Record) {
        let mut inner = self.lock();
        let waiting = inner
            .deletes
            .values()
            .filter(|r| r.node == record.node)
            .count();
        if waiting < MAX_DELETES_PER_NODE {
            inner.records.remove(&record.id);
            inner.deletes.insert(record.id, record);
        }
    }

    fn delete_done(&self, id: &SandboxId) {
        self.lock().deletes.remove(id);
    }

    fn held(&self, tenant: &str) -> (usize, u64) {
        self.lock().held(tenant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(tenant: &str, node: &str) -> Record {
        Record {
            id: SandboxId::random().unwrap(),
            tenant: tenant.into(),
            node: node.into(),
            template: "python".into(),
            memory_limit: 100,
        }
    }

    #[test]
    fn reservations_count_against_the_limit() {
        let store = MemoryStore::default();
        let one = store.reserve("a", 2, 100, None).unwrap();
        store.insert(record("a", "n"));
        assert_eq!(store.reserve("a", 2, 100, None).err(), Some(Refused::Count));
        assert!(store.reserve("b", 2, 100, None).is_ok());
        drop(one);
        assert!(store.reserve("a", 2, 100, None).is_ok());
    }

    #[test]
    fn memory_is_reserved_with_the_slot() {
        let store = MemoryStore::default();
        store.insert(record("a", "n"));
        let one = store.reserve("a", 10, 150, Some(300)).unwrap();
        assert_eq!(store.held("a"), (2, 250));
        assert_eq!(
            store.reserve("a", 10, 51, Some(300)).err(),
            Some(Refused::Memory)
        );
        let two = store.reserve("a", 10, 50, Some(300)).unwrap();
        assert_eq!(store.held("a"), (3, 300));
        drop((one, two));
        assert_eq!(store.held("a"), (1, 100));
        assert_eq!(store.held("b"), (0, 0));
    }

    #[test]
    fn a_delete_for_later_frees_the_slot_and_is_not_listed_again() {
        let store = MemoryStore::default();
        let r = record("a", "n");
        store.insert(r.clone());
        assert_eq!(store.delete_later(&r.id), Some(r.clone()));
        assert_eq!(store.held("a"), (0, 0));
        assert_eq!(store.get(&r.id), None);
        assert!(store.delete_later(&r.id).is_none(), "once");
        // The node, back, still lists it: it does not come back.
        store.replace_node("n", Instant::now(), vec![r.clone()]);
        assert_eq!(store.get(&r.id), None);
        assert!(store.of_tenant("a").is_empty());
        assert_eq!(store.deletes(), vec![r.clone()]);
        store.delete_done(&r.id);
        assert!(store.deletes().is_empty());
        // Bounded per node.
        for _ in 0..MAX_DELETES_PER_NODE {
            let x = record("a", "full");
            store.insert(x.clone());
            assert!(store.delete_later(&x.id).is_some());
        }
        let x = record("a", "full");
        store.insert(x.clone());
        assert!(store.delete_later(&x.id).is_none());
        assert_eq!(store.get(&x.id), Some(x), "still there");
    }

    #[test]
    fn reconciliation_keeps_what_is_newer_than_the_question() {
        let store = MemoryStore::default();
        let old = record("a", "n");
        let other_node = record("a", "m");
        store.insert(old.clone());
        store.insert(other_node.clone());
        let asked = Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let newer = record("a", "n");
        store.insert(newer.clone());
        let reported = record("b", "n");
        store.replace_node("n", asked, vec![reported.clone()]);
        assert_eq!(store.get(&old.id), None, "ended on the node");
        assert_eq!(store.ended(&old.id), Some(old.clone()), "and remembered");
        assert_eq!(store.ended(&newer.id), None);
        assert!(store.get(&newer.id).is_some(), "created after the question");
        assert!(store.get(&other_node.id).is_some(), "another node's");
        assert_eq!(store.get(&reported.id), Some(reported));
    }
}
