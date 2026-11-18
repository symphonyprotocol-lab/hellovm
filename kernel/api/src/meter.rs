//! Metering: what each tenant's sandboxes used in the current period.
//!
//! The nodes measure (see `noded`); every probe brings each sandbox's
//! counters, which only grow, and the final counters of the sandboxes
//! that ended. The meter keeps, per sandbox, the last counters it took (a
//! *track*) and adds what grew since to the tenant's totals for the period
//! and to a record not yet written. Records go to the usage log
//! ([`crate::meterlog`]) every `interval`, when a sandbox ends, and at the
//! end of a period, so the records of a period add up to its totals.
//!
//! A node is not trusted to report sense. Every counter of a sample is
//! checked against the one before: one that went down is not counted (the
//! track keeps the higher value, so nothing is counted twice when it comes
//! back up), and one that grew more than possible in the time since (CPU
//! time faster than the node's CPUs, run time faster than the clock, egress
//! faster than 100 Gbit/s, memory beyond the node's memory) is counted only
//! up to that bound. A sandbox belongs to the tenant and node it was first
//! seen with; a report of it with another tenant or node is ignored.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use hellovm_control::ids::SandboxId;
use hellovm_control::types::{Period, SandboxUsage as Counters};
use serde::{Deserialize, Serialize};

/// Run time a sample may add beyond the time since the last one: the node
/// measured at its own moments.
const SLACK_MS: u64 = 30_000;
/// Egress bytes per second a sandbox can move (100 Gbit/s).
const MAX_BYTES_PER_SECOND: u64 = 12_500_000_000;
/// Largest counter taken (beyond what a JSON number holds exactly).
pub const MAX_COUNTER: u64 = 1 << 53;
/// Sandboxes tracked at once (live, or ended and not yet final).
pub const MAX_TRACKS: usize = 65536;
/// Ended sandboxes remembered, so that a late report does not count them
/// again.
const MAX_CLOSED: usize = 65536;
/// A sandbox its node has not reported, live or ended, for this long
/// (while the node answers) is taken as gone with what was counted.
pub const LOST_AFTER: Duration = Duration::from_secs(60);

/// The start of the period that holds `unix_secs`.
pub fn period_start(unix_secs: u64, period: u64) -> u64 {
    unix_secs - unix_secs % period.max(1)
}

/// A period as the API reports it.
pub fn period_view(start: u64, period: u64) -> Period {
    Period {
        start: start * 1000,
        end: (start + period) * 1000,
        seconds: period,
    }
}

/// `YYYYMMDDTHHMMSSZ` for a Unix time (UTC).
pub fn utc_stamp(unix_secs: u64) -> String {
    let days = (unix_secs / 86400) as i64;
    let rem = unix_secs % 86400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

pub fn add(a: &Counters, b: &Counters) -> Counters {
    Counters {
        run_ms: a.run_ms.saturating_add(b.run_ms),
        cpu_ms: a.cpu_ms.saturating_add(b.cpu_ms),
        memory_byte_seconds: a.memory_byte_seconds.saturating_add(b.memory_byte_seconds),
        egress_sent_bytes: a.egress_sent_bytes.saturating_add(b.egress_sent_bytes),
        egress_received_bytes: a
            .egress_received_bytes
            .saturating_add(b.egress_received_bytes),
    }
}

fn is_zero(c: &Counters) -> bool {
    *c == Counters::default()
}

/// What a node may report in a given time.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    pub cpus: u64,
    pub memory_bytes: u64,
}

/// What a sample adds to a track whose counters were `before`, `elapsed`
/// ms ago: the growth of each counter, at most what is possible in that
/// time; and the counters the track keeps. Whether anything was not
/// sense.
pub fn grow(
    before: &Counters,
    now: &Counters,
    elapsed_ms: u64,
    b: &Bounds,
) -> (Counters, Counters, bool) {
    let ms = elapsed_ms.saturating_add(SLACK_MS);
    let mut odd = false;
    let mut one = |old: u64, new: u64, max: u64| -> (u64, u64) {
        if new < old {
            odd = true;
            return (0, old);
        }
        let d = new - old;
        if d > max {
            odd = true;
            return (max, new);
        }
        (d, new)
    };
    let (run_ms, run_kept) = one(before.run_ms, now.run_ms, ms);
    let (cpu_ms, cpu_kept) = one(before.cpu_ms, now.cpu_ms, ms.saturating_mul(b.cpus.max(1)));
    let (mem, mem_kept) = one(
        before.memory_byte_seconds,
        now.memory_byte_seconds,
        (u128::from(b.memory_bytes) * u128::from(ms) / 1000).min(u128::from(u64::MAX)) as u64,
    );
    let bytes = (u128::from(MAX_BYTES_PER_SECOND) * u128::from(ms) / 1000) as u64;
    let (sent, sent_kept) = one(before.egress_sent_bytes, now.egress_sent_bytes, bytes);
    let (recv, recv_kept) = one(
        before.egress_received_bytes,
        now.egress_received_bytes,
        bytes,
    );
    (
        Counters {
            run_ms,
            cpu_ms,
            memory_byte_seconds: mem,
            egress_sent_bytes: sent,
            egress_received_bytes: recv,
        },
        Counters {
            run_ms: run_kept,
            cpu_ms: cpu_kept,
            memory_byte_seconds: mem_kept,
            egress_sent_bytes: sent_kept,
            egress_received_bytes: recv_kept,
        },
        odd,
    )
}

/// What a record says.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// What a running sandbox used since its last record.
    Usage,
    /// Its last record: it ended (`end` says how we know).
    Final,
    /// At the start of a period: its counters so far (`delta` is zero).
    Carry,
    /// Its tenant deleted it while its node was unreachable; it is deleted
    /// on the node once the node answers.
    DeletePending,
    /// That delete was done (or the node no longer has it).
    DeleteDone,
}

/// One line of the usage log.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// The format's version: 1.
    pub v: u32,
    pub kind: Kind,
    /// When it was made, Unix ms.
    pub ts: u64,
    /// The period it counts in: its start, Unix seconds.
    pub period: u64,
    pub tenant: String,
    pub sandbox: String,
    pub node: String,
    #[serde(default)]
    pub template: String,
    /// Used since the sandbox's previous record (`usage`, `final`).
    #[serde(default)]
    pub delta: Counters,
    /// The sandbox's counters so far, as its node reported them.
    #[serde(default)]
    pub total: Counters,
    /// Its memory at the last measurement.
    #[serde(default)]
    pub memory_bytes: u64,
    /// With `final`: `ended` (its node reported its end) or `lost` (it
    /// vanished: its node restarted, or did not report it for a minute).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
}

/// A record to write: its period and its line (without the newline).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    pub period: u64,
    pub text: String,
}

/// One sandbox as a node reported it.
#[derive(Clone, Debug)]
pub struct Observed {
    pub id: SandboxId,
    pub tenant: String,
    pub template: String,
    pub usage: Counters,
    pub memory_bytes: u64,
    pub memory_limit: u64,
    /// Unix ms (the node's clock).
    pub created_at: u64,
}

struct Track {
    tenant: String,
    node: String,
    template: String,
    /// The counters taken last.
    total: Counters,
    /// Grown since the last record.
    pending: Counters,
    memory_bytes: u64,
    memory_limit: u64,
    /// When `total` was taken.
    at: Instant,
    /// When its node last reported it.
    seen: Instant,
}

/// What the log said at start-up.
#[derive(Default, Debug)]
pub struct Rebuilt {
    /// The current period's totals per tenant.
    pub totals: HashMap<String, Counters>,
    /// The last counters of sandboxes with no final record: `(tenant,
    /// node, template, total, ts)`.
    pub baselines: HashMap<SandboxId, (String, String, String, Counters, u64)>,
    /// Sandboxes with a final record.
    pub closed: Vec<SandboxId>,
    /// Deletes not done: `(tenant, node)`.
    pub deletes: HashMap<SandboxId, (String, String)>,
    pub records: u64,
    /// Lines that were not records (or of an unknown tenant).
    pub bad: u64,
    /// More was there than `max_read_mb`.
    pub truncated: bool,
}

impl Rebuilt {
    /// Takes in one line of the log of `period` (the current one when
    /// `current`).
    pub fn take(&mut self, line: &str, current: bool, known: &dyn Fn(&str) -> bool) {
        let Ok(r) = serde_json::from_str::<Record>(line) else {
            self.bad += 1;
            return;
        };
        let Some(id) = SandboxId::parse(&r.sandbox) else {
            self.bad += 1;
            return;
        };
        if r.v != 1 || !known(&r.tenant) {
            self.bad += 1;
            return;
        }
        self.records += 1;
        match r.kind {
            Kind::Usage | Kind::Final | Kind::Carry => {
                if current {
                    let t = self.totals.entry(r.tenant.clone()).or_default();
                    *t = add(t, &r.delta);
                }
                if r.kind == Kind::Final {
                    self.baselines.remove(&id);
                    self.closed.push(id);
                } else if self.baselines.len() < MAX_TRACKS || self.baselines.contains_key(&id) {
                    self.baselines
                        .insert(id, (r.tenant, r.node, r.template, r.total, r.ts));
                }
            }
            Kind::DeletePending => {
                if self.deletes.len() < MAX_TRACKS {
                    self.deletes.insert(id, (r.tenant, r.node));
                }
            }
            Kind::DeleteDone => {
                self.deletes.remove(&id);
            }
        }
    }
}

/// The meter: per-tenant totals of the current period, and what is known
/// of each sandbox.
pub struct Meter {
    period: u64,
    /// The current period's start, Unix seconds.
    start: u64,
    totals: HashMap<String, Counters>,
    tracks: HashMap<SandboxId, Track>,
    closed: HashSet<SandboxId>,
    closed_order: VecDeque<SandboxId>,
    /// Per node: its boot number and the `seq` of the last ended sandbox
    /// taken.
    cursors: HashMap<String, (u64, u64)>,
    /// Records not yet handed to the log.
    out: Vec<Line>,
    /// Whether there is a log (to rebuild from after a restart).
    logged: bool,
    /// When this process started, Unix ms.
    started_ms: u64,
    max_lifetime_ms: u64,
    tenants: HashSet<String>,
    /// Samples that were not sense, since start.
    pub odd: u64,
}

impl Meter {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        period: u64,
        now_ms: u64,
        now: Instant,
        logged: bool,
        max_lifetime_ms: u64,
        tenants: Vec<String>,
        rebuilt: &Rebuilt,
    ) -> Meter {
        let mut meter = Meter {
            period,
            start: period_start(now_ms / 1000, period),
            totals: rebuilt.totals.clone(),
            tracks: HashMap::new(),
            closed: HashSet::new(),
            closed_order: VecDeque::new(),
            cursors: HashMap::new(),
            out: Vec::new(),
            logged,
            started_ms: now_ms,
            max_lifetime_ms,
            tenants: tenants.into_iter().collect(),
            odd: 0,
        };
        for id in &rebuilt.closed {
            meter.close(*id);
        }
        for (id, (tenant, node, template, total, ts)) in &rebuilt.baselines {
            let ago = Duration::from_millis(now_ms.saturating_sub(*ts));
            let at = now.checked_sub(ago).unwrap_or(now);
            meter.tracks.insert(
                *id,
                Track {
                    tenant: tenant.clone(),
                    node: node.clone(),
                    template: template.clone(),
                    total: *total,
                    pending: Counters::default(),
                    memory_bytes: 0,
                    memory_limit: 0,
                    at,
                    seen: now,
                },
            );
        }
        meter
    }

    pub fn period(&self) -> Period {
        period_view(self.start, self.period)
    }

    fn close(&mut self, id: SandboxId) {
        if self.closed.insert(id) {
            self.closed_order.push_back(id);
            if self.closed_order.len() > MAX_CLOSED {
                if let Some(old) = self.closed_order.pop_front() {
                    self.closed.remove(&old);
                }
            }
        }
    }

    /// The `ended_after` to ask node `node` with.
    pub fn cursor(&self, node: &str) -> u64 {
        self.cursors.get(node).map_or(0, |c| c.1)
    }

    /// The boot number node `node` reported last.
    pub fn boot(&self, node: &str) -> Option<u64> {
        self.cursors.get(node).map(|c| c.0)
    }

    fn record(
        &mut self,
        kind: Kind,
        now_ms: u64,
        id: &SandboxId,
        t: &Track,
        delta: Counters,
        end: Option<&str>,
    ) {
        let record = Record {
            v: 1,
            kind,
            ts: now_ms,
            period: self.start,
            tenant: t.tenant.clone(),
            sandbox: id.to_string(),
            node: t.node.clone(),
            template: t.template.clone(),
            delta,
            total: t.total,
            memory_bytes: t.memory_bytes,
            end: end.map(str::to_string),
        };
        if let Ok(text) = serde_json::to_string(&record) {
            self.out.push(Line {
                period: self.start,
                text,
            });
        }
    }

    /// A delete accepted for a sandbox of an unreachable node, or done.
    pub fn note_delete(
        &mut self,
        now_ms: u64,
        id: &SandboxId,
        tenant: &str,
        node: &str,
        done: bool,
    ) {
        let record = Record {
            v: 1,
            kind: if done {
                Kind::DeleteDone
            } else {
                Kind::DeletePending
            },
            ts: now_ms,
            period: self.start,
            tenant: tenant.to_string(),
            sandbox: id.to_string(),
            node: node.to_string(),
            template: String::new(),
            delta: Counters::default(),
            total: Counters::default(),
            memory_bytes: 0,
            end: None,
        };
        if let Ok(text) = serde_json::to_string(&record) {
            self.out.push(Line {
                period: self.start,
                text,
            });
        }
    }

    /// Takes a probe's report of `node`: its live sandboxes, those that
    /// ended (with `seq`s up to `last_seq`), its `boot`; `complete` when
    /// the list of ended ones was not cut short.
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        &mut self,
        node: &str,
        now_ms: u64,
        now: Instant,
        bounds: &Bounds,
        live: Vec<Observed>,
        ended: Vec<Observed>,
        boot: u64,
        last_seq: u64,
        complete: bool,
    ) {
        let restarted = self.cursors.get(node).is_some_and(|&(b, _)| b != boot);
        self.cursors.insert(node.to_string(), (boot, last_seq));
        if restarted {
            // Its sandboxes died with it: what they used since the last
            // probe is lost.
            let gone: Vec<SandboxId> = self
                .tracks
                .iter()
                .filter(|(_, t)| t.node == node)
                .map(|(id, _)| *id)
                .collect();
            for id in gone {
                self.finish(id, now_ms, "lost");
            }
        }
        for o in live {
            self.sample(node, now_ms, now, bounds, &o);
        }
        for o in ended {
            // The node lists what ended before (on first contact, all it
            // remembers): one made before the time this meter counts was
            // counted then, if at all.
            if !self.tracks.contains_key(&o.id) && o.created_at < self.count_from() {
                self.close(o.id);
                continue;
            }
            if self.sample(node, now_ms, now, bounds, &o) {
                self.finish(o.id, now_ms, "ended");
            }
        }
        if complete {
            let lost: Vec<SandboxId> = self
                .tracks
                .iter()
                .filter(|(_, t)| {
                    t.node == node && now.saturating_duration_since(t.seen) >= LOST_AFTER
                })
                .map(|(id, _)| *id)
                .collect();
            for id in lost {
                self.finish(id, now_ms, "lost");
            }
        }
    }

    /// Usage from before this time is not counted for a sandbox first seen
    /// now (it was counted by the API before, or belongs to another
    /// period).
    fn count_from(&self) -> u64 {
        if self.logged {
            self.start * 1000
        } else {
            (self.start * 1000).max(self.started_ms)
        }
    }

    /// Takes one sandbox's counters; whether it is (now) tracked.
    fn sample(
        &mut self,
        node: &str,
        now_ms: u64,
        now: Instant,
        bounds: &Bounds,
        o: &Observed,
    ) -> bool {
        if self.closed.contains(&o.id) || !self.tenants.contains(&o.tenant) {
            return false;
        }
        let usage = Counters {
            run_ms: o.usage.run_ms.min(MAX_COUNTER),
            cpu_ms: o.usage.cpu_ms.min(MAX_COUNTER),
            memory_byte_seconds: o.usage.memory_byte_seconds.min(MAX_COUNTER),
            egress_sent_bytes: o.usage.egress_sent_bytes.min(MAX_COUNTER),
            egress_received_bytes: o.usage.egress_received_bytes.min(MAX_COUNTER),
        };
        let delta = match self.tracks.get_mut(&o.id) {
            Some(t) => {
                if t.tenant != o.tenant || t.node != node {
                    self.odd += 1;
                    return false;
                }
                let elapsed = now.saturating_duration_since(t.at).as_millis() as u64;
                let (delta, kept, odd) = grow(&t.total, &usage, elapsed, bounds);
                if odd {
                    self.odd += 1;
                }
                t.total = kept;
                t.pending = add(&t.pending, &delta);
                t.memory_bytes = o.memory_bytes;
                t.memory_limit = o.memory_limit;
                t.at = now;
                t.seen = now;
                delta
            }
            None => {
                if self.tracks.len() >= MAX_TRACKS {
                    self.odd += 1;
                    return false;
                }
                // First seen: from zero if it was made in the time this
                // meter counts, else from now.
                let (delta, kept) = if o.created_at >= self.count_from() {
                    let elapsed = usage.run_ms.min(self.max_lifetime_ms);
                    let (delta, kept, odd) = grow(&Counters::default(), &usage, elapsed, bounds);
                    if odd {
                        self.odd += 1;
                    }
                    (delta, kept)
                } else {
                    (Counters::default(), usage)
                };
                self.tracks.insert(
                    o.id,
                    Track {
                        tenant: o.tenant.clone(),
                        node: node.to_string(),
                        template: o.template.clone(),
                        total: kept,
                        pending: delta,
                        memory_bytes: o.memory_bytes,
                        memory_limit: o.memory_limit,
                        at: now,
                        seen: now,
                    },
                );
                delta
            }
        };
        let _ = now_ms;
        let t = self.totals.entry(o.tenant.clone()).or_default();
        *t = add(t, &delta);
        true
    }

    /// Writes a sandbox's last record and forgets it.
    fn finish(&mut self, id: SandboxId, now_ms: u64, end: &str) {
        if let Some(t) = self.tracks.remove(&id) {
            let delta = t.pending;
            self.record(Kind::Final, now_ms, &id, &t, delta, Some(end));
        }
        self.close(id);
    }

    /// Once a second: starts a new period when one began (the old one's
    /// pending usage is recorded in it, and every sandbox's counters and
    /// every delete still to do are carried into the new one), and records
    /// what running sandboxes used when `flush` (every `interval`).
    pub fn tick(&mut self, now_ms: u64, flush: bool, deletes: &[(SandboxId, String, String)]) {
        let start = period_start(now_ms / 1000, self.period);
        if start != self.start {
            self.flush(now_ms);
            self.start = start;
            self.totals.clear();
            let ids: Vec<SandboxId> = self.tracks.keys().copied().collect();
            for id in ids {
                if let Some(t) = self.tracks.remove(&id) {
                    self.record(Kind::Carry, now_ms, &id, &t, Counters::default(), None);
                    self.tracks.insert(id, t);
                }
            }
            for (id, tenant, node) in deletes {
                self.note_delete(now_ms, id, tenant, node, false);
            }
        } else if flush {
            self.flush(now_ms);
        }
    }

    fn flush(&mut self, now_ms: u64) {
        let ids: Vec<SandboxId> = self
            .tracks
            .iter()
            .filter(|(_, t)| !is_zero(&t.pending))
            .map(|(id, _)| *id)
            .collect();
        for id in ids {
            if let Some(mut t) = self.tracks.remove(&id) {
                let delta = std::mem::take(&mut t.pending);
                self.record(Kind::Usage, now_ms, &id, &t, delta, None);
                self.tracks.insert(id, t);
            }
        }
    }

    /// The records made since the last call.
    pub fn take_lines(&mut self) -> Vec<Line> {
        std::mem::take(&mut self.out)
    }

    /// A tenant's totals for the period that holds `now_ms` (zero when the
    /// meter has not started that period yet).
    pub fn totals(&self, tenant: &str, now_ms: u64) -> Counters {
        if period_start(now_ms / 1000, self.period) != self.start {
            return Counters::default();
        }
        self.totals.get(tenant).copied().unwrap_or_default()
    }

    /// The memory now of a tenant's sandboxes, by the last reports.
    pub fn memory_bytes(&self, tenant: &str) -> u64 {
        self.tracks
            .values()
            .filter(|t| t.tenant == tenant)
            .map(|t| t.memory_bytes)
            .fold(0, u64::saturating_add)
    }

    /// Seconds until the period that holds `now_ms` ends.
    pub fn seconds_left(&self, now_ms: u64) -> u64 {
        let start = period_start(now_ms / 1000, self.period);
        (start + self.period).saturating_sub(now_ms / 1000).max(1)
    }

    pub fn tracked(&self) -> usize {
        self.tracks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOUNDS: Bounds = Bounds {
        cpus: 4,
        memory_bytes: 1 << 30,
    };

    fn usage(run_ms: u64, cpu_ms: u64, sent: u64) -> Counters {
        Counters {
            run_ms,
            cpu_ms,
            memory_byte_seconds: run_ms / 1000 * 1000,
            egress_sent_bytes: sent,
            egress_received_bytes: sent / 2,
        }
    }

    fn observed(id: SandboxId, tenant: &str, u: Counters, created_at: u64) -> Observed {
        Observed {
            id,
            tenant: tenant.into(),
            template: "python".into(),
            usage: u,
            memory_bytes: 1000,
            memory_limit: 1 << 20,
            created_at,
        }
    }

    fn meter(now_ms: u64, now: Instant, logged: bool) -> Meter {
        Meter::new(
            3600,
            now_ms,
            now,
            logged,
            86_400_000,
            vec!["a".into(), "b".into()],
            &Rebuilt::default(),
        )
    }

    fn records(m: &mut Meter) -> Vec<Record> {
        m.take_lines()
            .iter()
            .map(|l| serde_json::from_str(&l.text).unwrap())
            .collect()
    }

    // 2026-11-18 00:00:00 UTC.
    const T0: u64 = 1_794_960_000_000;

    #[test]
    fn stamps_and_periods() {
        assert_eq!(utc_stamp(0), "19700101T000000Z");
        assert_eq!(utc_stamp(T0 / 1000), "20261118T000000Z");
        assert_eq!(utc_stamp(951_782_400 + 3661), "20000229T010101Z");
        assert_eq!(period_start(T0 / 1000 + 5000, 3600), T0 / 1000 + 3600);
        assert_eq!(period_start(7, 1), 7);
        let p = period_view(T0 / 1000, 86400);
        assert_eq!((p.start, p.end), (T0, T0 + 86_400_000));
    }

    #[test]
    fn growth_is_checked() {
        let a = usage(1000, 500, 100);
        let b = usage(3000, 2000, 400);
        let (d, kept, odd) = grow(&a, &b, 2000, &BOUNDS);
        assert!(!odd);
        assert_eq!(kept, b);
        assert_eq!((d.run_ms, d.cpu_ms, d.egress_sent_bytes), (2000, 1500, 300));
        // Backwards: nothing counted, the higher value kept.
        let (d, kept, odd) = grow(&b, &a, 2000, &BOUNDS);
        assert!(odd);
        assert_eq!(d, Counters::default());
        assert_eq!(kept, b);
        // Absurd: counted up to the bound.
        let absurd = Counters {
            cpu_ms: 1 << 50,
            ..b
        };
        let (d, kept, odd) = grow(&b, &absurd, 1000, &BOUNDS);
        assert!(odd);
        assert_eq!(d.cpu_ms, (1000 + SLACK_MS) * 4);
        assert_eq!(kept.cpu_ms, 1 << 50);
        let (d, _, odd) = grow(
            &Counters::default(),
            &usage(u64::MAX, 0, u64::MAX),
            0,
            &BOUNDS,
        );
        assert!(odd);
        assert_eq!(d.run_ms, SLACK_MS);
    }

    #[test]
    fn usage_is_counted_per_tenant_and_recorded() {
        let now = Instant::now();
        let mut m = meter(T0 + 1000, now, true);
        let (x, y) = (SandboxId::random().unwrap(), SandboxId::random().unwrap());
        m.observe(
            "n1",
            T0 + 1000,
            now,
            &BOUNDS,
            vec![
                observed(x, "a", usage(1000, 100, 10), T0),
                observed(y, "b", usage(500, 50, 0), T0),
            ],
            vec![],
            7,
            0,
            true,
        );
        assert_eq!(m.totals("a", T0 + 1000).cpu_ms, 100);
        assert_eq!(m.totals("b", T0 + 1000).cpu_ms, 50);
        let later = now + Duration::from_secs(2);
        m.observe(
            "n1",
            T0 + 3000,
            later,
            &BOUNDS,
            vec![observed(x, "a", usage(3000, 900, 30), T0)],
            vec![],
            7,
            0,
            true,
        );
        assert_eq!(m.totals("a", T0 + 3000).cpu_ms, 900);
        assert_eq!(m.totals("b", T0 + 3000).cpu_ms, 50, "untouched");
        // A report of x for another tenant, or from another node: ignored.
        m.observe(
            "n1",
            T0 + 3000,
            later,
            &BOUNDS,
            vec![observed(x, "b", usage(9000, 9000, 0), T0)],
            vec![],
            7,
            0,
            true,
        );
        m.observe(
            "n2",
            T0 + 3000,
            later,
            &BOUNDS,
            vec![observed(x, "a", usage(9000, 9000, 0), T0)],
            vec![],
            1,
            0,
            true,
        );
        assert_eq!(m.totals("a", T0 + 3000).cpu_ms, 900);
        assert_eq!(m.totals("b", T0 + 3000).cpu_ms, 50);
        assert_eq!(m.odd, 2);
        m.tick(T0 + 4000, true, &[]);
        let r = records(&mut m);
        assert_eq!(r.len(), 2);
        let rx = r.iter().find(|r| r.sandbox == x.to_string()).unwrap();
        assert_eq!(
            (
                rx.kind,
                rx.tenant.as_str(),
                rx.delta.cpu_ms,
                rx.total.cpu_ms
            ),
            (Kind::Usage, "a", 900, 900)
        );
        // Nothing grew: no record.
        m.tick(T0 + 5000, true, &[]);
        assert!(records(&mut m).is_empty());
        // x ends: its last growth in a final record, and never again.
        let end = observed(x, "a", usage(4000, 1000, 40), T0);
        m.observe(
            "n1",
            T0 + 5000,
            later + Duration::from_secs(2),
            &BOUNDS,
            vec![],
            vec![end.clone()],
            7,
            1,
            true,
        );
        let r = records(&mut m);
        assert_eq!(r.len(), 1);
        assert_eq!(
            (r[0].kind, r[0].delta.cpu_ms, r[0].end.as_deref()),
            (Kind::Final, 100, Some("ended"))
        );
        m.observe(
            "n1",
            T0 + 6000,
            later + Duration::from_secs(3),
            &BOUNDS,
            vec![observed(x, "a", usage(9000, 5000, 0), T0)],
            vec![end],
            7,
            1,
            true,
        );
        assert_eq!(m.totals("a", T0 + 6000).cpu_ms, 1000);
        assert!(records(&mut m).is_empty());
        // Unknown tenants are not metered.
        let z = SandboxId::random().unwrap();
        m.observe(
            "n1",
            T0 + 6000,
            later,
            &BOUNDS,
            vec![observed(z, "zz", usage(1, 1, 1), T0)],
            vec![],
            7,
            1,
            true,
        );
        assert_eq!(m.tracked(), 1);
    }

    #[test]
    fn periods_roll_over_and_carry() {
        let now = Instant::now();
        let mut m = meter(T0 + 3_599_000, now, true);
        let x = SandboxId::random().unwrap();
        m.observe(
            "n1",
            T0 + 3_599_000,
            now,
            &BOUNDS,
            vec![observed(x, "a", usage(1000, 500, 0), T0)],
            vec![],
            1,
            0,
            true,
        );
        assert_eq!(m.totals("a", T0 + 3_599_000).cpu_ms, 500);
        // The next period began, the meter has not ticked yet: zero.
        assert_eq!(m.totals("a", T0 + 3_600_500).cpu_ms, 0);
        let deletes = vec![(
            SandboxId::random().unwrap(),
            "a".to_string(),
            "n2".to_string(),
        )];
        m.tick(T0 + 3_600_500, false, &deletes);
        let r = records(&mut m);
        assert_eq!(r.len(), 3);
        assert_eq!(
            (r[0].kind, r[0].period, r[0].delta.cpu_ms),
            (Kind::Usage, T0 / 1000, 500)
        );
        assert_eq!(
            (r[1].kind, r[1].period, r[1].total.cpu_ms),
            (Kind::Carry, T0 / 1000 + 3600, 500)
        );
        assert_eq!(
            (r[2].kind, r[2].period),
            (Kind::DeletePending, T0 / 1000 + 3600)
        );
        assert_eq!(m.totals("a", T0 + 3_600_500), Counters::default());
        m.observe(
            "n1",
            T0 + 3_601_000,
            now + Duration::from_secs(2),
            &BOUNDS,
            vec![observed(x, "a", usage(3000, 700, 0), T0)],
            vec![],
            1,
            0,
            true,
        );
        assert_eq!(
            m.totals("a", T0 + 3_601_000).cpu_ms,
            200,
            "only the new period's"
        );
        assert_eq!(m.seconds_left(T0 + 3_601_000), 3599);
    }

    #[test]
    fn a_restart_rebuilds_from_the_log() {
        let now = Instant::now();
        let mut m = meter(T0 + 1000, now, true);
        let (x, y) = (SandboxId::random().unwrap(), SandboxId::random().unwrap());
        m.observe(
            "n1",
            T0 + 1000,
            now,
            &BOUNDS,
            vec![
                observed(x, "a", usage(1000, 400, 0), T0),
                observed(y, "a", usage(1000, 100, 0), T0),
            ],
            vec![],
            1,
            0,
            true,
        );
        m.tick(T0 + 2000, true, &[]);
        let end = observed(y, "a", usage(2000, 150, 0), T0);
        m.observe(
            "n1",
            T0 + 2000,
            now + Duration::from_secs(1),
            &BOUNDS,
            vec![],
            vec![end.clone()],
            1,
            1,
            true,
        );
        let id = SandboxId::random().unwrap();
        m.note_delete(T0 + 2000, &id, "a", "n2", false);
        let lines = m.take_lines();
        let mut rebuilt = Rebuilt::default();
        let known = |t: &str| t == "a" || t == "b";
        for l in &lines {
            rebuilt.take(&l.text, true, &known);
        }
        rebuilt.take("garbage", true, &known);
        rebuilt.take(&lines[0].text.replace("\"a\"", "\"other\""), true, &known);
        assert_eq!(rebuilt.bad, 2);
        assert_eq!(rebuilt.totals["a"].cpu_ms, 550);
        assert_eq!(rebuilt.closed, vec![y]);
        assert!(rebuilt.baselines.contains_key(&x));
        assert!(rebuilt.deletes.contains_key(&id));
        // The new process: x continues from its logged counters, y (whose
        // end the node still lists) is not counted again.
        let now2 = now + Duration::from_secs(5);
        let mut m2 = Meter::new(
            3600,
            T0 + 6000,
            now2,
            true,
            86_400_000,
            vec!["a".into()],
            &rebuilt,
        );
        assert_eq!(m2.totals("a", T0 + 6000).cpu_ms, 550);
        m2.observe(
            "n1",
            T0 + 6000,
            now2,
            &BOUNDS,
            vec![observed(x, "a", usage(6000, 1000, 0), T0)],
            vec![end],
            1,
            1,
            true,
        );
        assert_eq!(m2.totals("a", T0 + 6000).cpu_ms, 1150);
        let mut deleted = Rebuilt::default();
        m2.note_delete(T0 + 7000, &id, "a", "n2", true);
        for l in lines.iter().chain(m2.take_lines().iter()) {
            deleted.take(&l.text, true, &known);
        }
        assert!(deleted.deletes.is_empty());
    }

    #[test]
    fn first_sight_and_lost_sandboxes() {
        let now = Instant::now();
        // No log: a sandbox made before this process counts from now.
        let mut m = meter(T0 + 10_000, now, false);
        let (old, new) = (SandboxId::random().unwrap(), SandboxId::random().unwrap());
        m.observe(
            "n1",
            T0 + 10_000,
            now,
            &BOUNDS,
            vec![
                observed(old, "a", usage(9000, 4000, 0), T0),
                observed(new, "a", usage(1000, 300, 0), T0 + 10_500),
            ],
            vec![],
            1,
            0,
            true,
        );
        assert_eq!(m.totals("a", T0 + 10_000).cpu_ms, 300);
        // What ended before this process started is not counted.
        let gone = observed(SandboxId::random().unwrap(), "b", usage(1000, 999, 0), T0);
        m.observe(
            "n2",
            T0 + 10_000,
            now,
            &BOUNDS,
            vec![],
            vec![gone],
            1,
            1,
            true,
        );
        assert_eq!(m.totals("b", T0 + 10_000).cpu_ms, 0);
        // A node that restarted: its sandboxes are lost.
        m.observe(
            "n1",
            T0 + 11_000,
            now + Duration::from_secs(1),
            &BOUNDS,
            vec![],
            vec![],
            2,
            0,
            true,
        );
        assert_eq!(m.tracked(), 0);
        let r = records(&mut m);
        assert_eq!(r.len(), 2);
        assert!(r
            .iter()
            .all(|r| r.kind == Kind::Final && r.end.as_deref() == Some("lost")));
        // One not reported for a minute: lost too, but not before.
        let x = SandboxId::random().unwrap();
        m.observe(
            "n1",
            T0 + 12_000,
            now,
            &BOUNDS,
            vec![observed(x, "a", usage(1, 1, 0), T0 + 11_500)],
            vec![],
            2,
            0,
            true,
        );
        m.observe(
            "n1",
            T0 + 13_000,
            now + Duration::from_secs(30),
            &BOUNDS,
            vec![],
            vec![],
            2,
            0,
            true,
        );
        assert_eq!(m.tracked(), 1);
        m.observe(
            "n1",
            T0 + 13_000,
            now + Duration::from_secs(61),
            &BOUNDS,
            vec![],
            vec![],
            2,
            0,
            false,
        );
        assert_eq!(m.tracked(), 1, "an incomplete answer says nothing");
        m.observe(
            "n1",
            T0 + 13_000,
            now + Duration::from_secs(61),
            &BOUNDS,
            vec![],
            vec![],
            2,
            0,
            true,
        );
        assert_eq!(m.tracked(), 0);
    }
}
