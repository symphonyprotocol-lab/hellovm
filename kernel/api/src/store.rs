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

use std::collections::HashMap;
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
}

/// A slot of a tenant's sandbox limit held for a creation in progress.
pub struct Reservation<'a> {
    store: &'a dyn Store,
    tenant: String,
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        self.store.release(&self.tenant);
    }
}

pub trait Store: Send + Sync {
    /// Holds one of `tenant`'s `max` slots, or `None` when they are all
    /// taken by sandboxes and creations in progress.
    fn reserve(&self, tenant: &str, max: usize) -> Option<Reservation<'_>>;
    /// Gives a slot back (by dropping its [`Reservation`]).
    fn release(&self, tenant: &str);
    fn insert(&self, record: Record);
    fn get(&self, id: &SandboxId) -> Option<Record>;
    fn remove(&self, id: &SandboxId) -> Option<Record>;
    fn of_tenant(&self, tenant: &str) -> Vec<Record>;
    /// Makes the records of `node` what it reported at `asked` (records
    /// inserted after that are kept: the node's list predates them).
    fn replace_node(&self, node: &str, asked: Instant, records: Vec<Record>);
}

#[derive(Default)]
struct Inner {
    records: HashMap<SandboxId, (Record, Instant)>,
    pending: HashMap<String, usize>,
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
    fn reserve(&self, tenant: &str, max: usize) -> Option<Reservation<'_>> {
        let mut inner = self.lock();
        let have = inner
            .records
            .values()
            .filter(|(r, _)| r.tenant == tenant)
            .count();
        let pending = inner.pending.get(tenant).copied().unwrap_or(0);
        if have + pending >= max {
            return None;
        }
        *inner.pending.entry(tenant.to_string()).or_default() += 1;
        Some(Reservation {
            store: self,
            tenant: tenant.to_string(),
        })
    }

    fn release(&self, tenant: &str) {
        let mut inner = self.lock();
        if let Some(n) = inner.pending.get_mut(tenant) {
            *n = n.saturating_sub(1);
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
        self.lock().records.remove(id).map(|(r, _)| r)
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
        inner
            .records
            .retain(|_, (r, inserted)| r.node != node || *inserted > asked);
        for record in records.into_iter().filter(|r| r.node == node) {
            inner.records.entry(record.id).or_insert((record, asked));
        }
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
        }
    }

    #[test]
    fn reservations_count_against_the_limit() {
        let store = MemoryStore::default();
        let one = store.reserve("a", 2).unwrap();
        store.insert(record("a", "n"));
        assert!(store.reserve("a", 2).is_none());
        assert!(store.reserve("b", 2).is_some());
        drop(one);
        assert!(store.reserve("a", 2).is_some());
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
        assert!(store.get(&newer.id).is_some(), "created after the question");
        assert!(store.get(&other_node.id).is_some(), "another node's");
        assert_eq!(store.get(&reported.id), Some(reported));
    }
}
