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

/// How time is cut into metering periods (`metering.period`): a fixed
/// number of seconds, aligned to multiples of it since the Unix epoch, or
/// calendar months in UTC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Periods {
    Seconds(u64),
    Months,
}

impl From<u64> for Periods {
    fn from(seconds: u64) -> Periods {
        Periods::Seconds(seconds)
    }
}

impl Periods {
    /// The start of the period that holds `unix_secs` (Unix seconds).
    pub fn start_of(self, unix_secs: u64) -> u64 {
        match self {
            Periods::Seconds(p) => unix_secs - unix_secs % p.max(1),
            Periods::Months => {
                let (y, m, _) = civil_from_days((unix_secs / 86400) as i64);
                (days_from_civil(y, m, 1).max(0) as u64) * 86400
            }
        }
    }

    /// The start of the period after the one that starts at `start`.
    pub fn next(self, start: u64) -> u64 {
        match self {
            Periods::Seconds(p) => start.saturating_add(p.max(1)),
            Periods::Months => {
                let (y, m, _) = civil_from_days((start / 86400) as i64);
                let (y, m) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
                (days_from_civil(y, m, 1).max(0) as u64) * 86400
            }
        }
    }

    /// The start of the period before the one that starts at `start`
    /// (`None` before the epoch).
    pub fn previous(self, start: u64) -> Option<u64> {
        match self {
            Periods::Seconds(p) => start.checked_sub(p.max(1)),
            Periods::Months => {
                let (y, m, _) = civil_from_days((start / 86400) as i64);
                let (y, m) = if m == 1 { (y - 1, 12) } else { (y, m - 1) };
                u64::try_from(days_from_civil(y, m, 1))
                    .ok()
                    .map(|d| d * 86400)
            }
        }
    }
}

/// Howard Hinnant's civil_from_days: (year, month 1-12, day 1-31).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

/// Howard Hinnant's days_from_civil: days since 1970-01-01.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The start of the period that holds `unix_secs`.
pub fn period_start(unix_secs: u64, period: impl Into<Periods>) -> u64 {
    period.into().start_of(unix_secs)
}

/// The period that starts at `start` as the API reports it.
pub fn period_view(start: u64, period: impl Into<Periods>) -> Period {
    let end = period.into().next(start);
    Period {
        start: start * 1000,
        end: end * 1000,
        seconds: end - start,
    }
}

/// `YYYYMMDDTHHMMSSZ` for a Unix time (UTC).
pub fn utc_stamp(unix_secs: u64) -> String {
    let rem = unix_secs % 86400;
    let (year, month, day) = civil_from_days((unix_secs / 86400) as i64);
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
        ingress_received_bytes: a
            .ingress_received_bytes
            .saturating_add(b.ingress_received_bytes),
        ingress_sent_bytes: a.ingress_sent_bytes.saturating_add(b.ingress_sent_bytes),
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
    // Ingress is counted by the API itself (`Meter::ingress`), never
    // taken from a node: what the track has stays.
    (
        Counters {
            run_ms,
            cpu_ms,
            memory_byte_seconds: mem,
            egress_sent_bytes: sent,
            egress_received_bytes: recv,
            ingress_received_bytes: 0,
            ingress_sent_bytes: 0,
        },
        Counters {
            run_ms: run_kept,
            cpu_ms: cpu_kept,
            memory_byte_seconds: mem_kept,
            egress_sent_bytes: sent_kept,
            egress_received_bytes: recv_kept,
            ingress_received_bytes: before.ingress_received_bytes,
            ingress_sent_bytes: before.ingress_sent_bytes,
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
    /// Ingress bytes counted after its final record, or for a sandbox
    /// never reported by its node (its connections ended as it did):
    /// counted in the period's totals, nothing else.
    Late,
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

/// A sandbox closed as lost: where its counters stood, should its node
/// report it again.
struct Lost {
    tenant: String,
    node: String,
    template: String,
    total: Counters,
    at: Instant,
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
    /// Sandboxes whose last record is a final one.
    pub closed: HashSet<SandboxId>,
    /// Of those, the ones closed as `lost`, with their last counters: `(tenant,
    /// node, template, total, ts)`. One that its node reports again is
    /// counted on from there.
    pub lost: HashMap<SandboxId, (String, String, String, Counters, u64)>,
    /// Deletes not done: `(tenant, node)`.
    pub deletes: HashMap<SandboxId, (String, String)>,
    /// Sandboxes with a delete accepted (done or not) and no final record:
    /// what they use is not charged.
    pub freed: HashSet<SandboxId>,
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
                    self.freed.remove(&id);
                    self.closed.insert(id);
                    if r.end.as_deref() == Some("lost") && self.lost.len() < MAX_TRACKS {
                        self.lost
                            .insert(id, (r.tenant, r.node, r.template, r.total, r.ts));
                    } else {
                        self.lost.remove(&id);
                    }
                } else {
                    // A record after a final one: it was lost and came back.
                    self.closed.remove(&id);
                    self.lost.remove(&id);
                    if self.baselines.len() < MAX_TRACKS || self.baselines.contains_key(&id) {
                        self.baselines
                            .insert(id, (r.tenant, r.node, r.template, r.total, r.ts));
                    }
                }
            }
            Kind::DeletePending => {
                if self.deletes.len() < MAX_TRACKS {
                    self.deletes.insert(id, (r.tenant, r.node));
                }
                if self.freed.len() < MAX_TRACKS {
                    self.freed.insert(id);
                }
            }
            Kind::DeleteDone => {
                self.deletes.remove(&id);
            }
            Kind::Late => {
                if current {
                    let t = self.totals.entry(r.tenant.clone()).or_default();
                    *t = add(t, &r.delta);
                }
            }
        }
    }
}

/// The meter: per-tenant totals of the current period, and what is known
/// of each sandbox.
pub struct Meter {
    period: Periods,
    /// The current period's start, Unix seconds.
    start: u64,
    totals: HashMap<String, Counters>,
    tracks: HashMap<SandboxId, Track>,
    closed: HashSet<SandboxId>,
    closed_order: VecDeque<SandboxId>,
    /// Of the closed ones, those that were lost (not reported as ended).
    lost: HashMap<SandboxId, Lost>,
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
    /// Deleted by their tenant while their node did not answer: from then
    /// on what they use moves their counters and is not charged.
    free: HashSet<SandboxId>,
    /// Ingress counted for sandboxes not tracked yet (made and used before
    /// their node's next report): folded into their track when it comes.
    early: HashMap<SandboxId, Early>,
    /// Samples that were not sense, since start.
    pub odd: u64,
}

/// Ingress of a sandbox not tracked yet.
struct Early {
    tenant: String,
    node: String,
    template: String,
    counted: Counters,
    since: Instant,
}

impl Meter {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        period: impl Into<Periods>,
        now_ms: u64,
        now: Instant,
        logged: bool,
        max_lifetime_ms: u64,
        tenants: Vec<String>,
        rebuilt: &Rebuilt,
    ) -> Meter {
        let period = period.into();
        let mut meter = Meter {
            period,
            start: period.start_of(now_ms / 1000),
            totals: rebuilt.totals.clone(),
            tracks: HashMap::new(),
            closed: HashSet::new(),
            closed_order: VecDeque::new(),
            lost: HashMap::new(),
            cursors: HashMap::new(),
            out: Vec::new(),
            logged,
            started_ms: now_ms,
            max_lifetime_ms,
            tenants: tenants.into_iter().collect(),
            free: rebuilt.freed.clone(),
            early: HashMap::new(),
            odd: 0,
        };
        for id in &rebuilt.closed {
            meter.close(*id);
        }
        for (id, (tenant, node, template, total, ts)) in &rebuilt.lost {
            if meter.closed.contains(id) {
                let ago = Duration::from_millis(now_ms.saturating_sub(*ts));
                meter.lost.insert(
                    *id,
                    Lost {
                        tenant: tenant.clone(),
                        node: node.clone(),
                        template: template.clone(),
                        total: *total,
                        at: now.checked_sub(ago).unwrap_or(now),
                    },
                );
            }
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

    /// How periods are cut.
    pub fn periods(&self) -> Periods {
        self.period
    }

    fn close(&mut self, id: SandboxId) {
        if self.closed.insert(id) {
            self.closed_order.push_back(id);
            if self.closed_order.len() > MAX_CLOSED {
                if let Some(old) = self.closed_order.pop_front() {
                    self.closed.remove(&old);
                    self.lost.remove(&old);
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
        if !done && self.free.len() < MAX_TRACKS {
            // From now on its use is not its tenant's: what it used up to
            // the last report before the delete stays counted (and is
            // recorded now, before the delete, so that a restart that reads
            // the log back finds it), what it uses after (until its node
            // deletes it) moves its counters only.
            if let Some(mut t) = self.tracks.remove(id) {
                if !is_zero(&t.pending) {
                    let delta = std::mem::take(&mut t.pending);
                    self.record(Kind::Usage, now_ms, id, &t, delta, None);
                }
                self.tracks.insert(*id, t);
            }
            self.free.insert(*id);
        }
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
        if !self.tenants.contains(&o.tenant) {
            return false;
        }
        if self.closed.contains(&o.id) {
            // Closed as lost and reported again by the same node for the
            // same tenant: it lives, and is counted on from where its
            // counters stood. Anything else closed stays closed.
            let back = self
                .lost
                .get(&o.id)
                .is_some_and(|l| l.tenant == o.tenant && l.node == node);
            if !back || self.tracks.len() >= MAX_TRACKS {
                return false;
            }
            if let Some(l) = self.lost.remove(&o.id) {
                self.closed.remove(&o.id);
                self.closed_order.retain(|id| *id != o.id);
                self.tracks.insert(
                    o.id,
                    Track {
                        tenant: l.tenant,
                        node: l.node,
                        template: l.template,
                        total: l.total,
                        pending: Counters::default(),
                        memory_bytes: 0,
                        memory_limit: 0,
                        at: l.at,
                        seen: now,
                    },
                );
            }
        }
        let usage = Counters {
            run_ms: o.usage.run_ms.min(MAX_COUNTER),
            cpu_ms: o.usage.cpu_ms.min(MAX_COUNTER),
            memory_byte_seconds: o.usage.memory_byte_seconds.min(MAX_COUNTER),
            egress_sent_bytes: o.usage.egress_sent_bytes.min(MAX_COUNTER),
            egress_received_bytes: o.usage.egress_received_bytes.min(MAX_COUNTER),
            ingress_received_bytes: 0,
            ingress_sent_bytes: 0,
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
                t.memory_bytes = o.memory_bytes;
                t.memory_limit = o.memory_limit;
                t.at = now;
                t.seen = now;
                if self.free.contains(&o.id) {
                    // Deleted: its counters move on, uncharged.
                    return true;
                }
                t.pending = add(&t.pending, &delta);
                delta
            }
            None => {
                if self.tracks.len() >= MAX_TRACKS {
                    self.odd += 1;
                    return false;
                }
                // First seen: from zero if it was made in the time this
                // meter counts, else from now. What it may have used is
                // bounded by the time this meter counts, not only by the
                // run time its node reports: the node is not trusted with
                // its own bound.
                let (delta, kept) = if self.free.contains(&o.id) {
                    (Counters::default(), usage)
                } else if o.created_at >= self.count_from() {
                    let elapsed = usage
                        .run_ms
                        .min(self.max_lifetime_ms)
                        .min(now_ms.saturating_sub(self.count_from()));
                    let (delta, kept, odd) = grow(&Counters::default(), &usage, elapsed, bounds);
                    if odd {
                        self.odd += 1;
                    }
                    (delta, kept)
                } else {
                    (Counters::default(), usage)
                };
                // Ingress counted before it was tracked (in the totals
                // already) joins its counters and its next record.
                let (mut kept, mut pending) = (kept, delta);
                if let Some(e) = self.early.remove(&o.id) {
                    if e.tenant == o.tenant && e.node == node {
                        kept = add(&kept, &e.counted);
                        pending = add(&pending, &e.counted);
                    } else {
                        self.late(now_ms, &o.id, &e.tenant, &e.node, &e.template, e.counted);
                    }
                }
                self.tracks.insert(
                    o.id,
                    Track {
                        tenant: o.tenant.clone(),
                        node: node.to_string(),
                        template: o.template.clone(),
                        total: kept,
                        pending,
                        memory_bytes: o.memory_bytes,
                        memory_limit: o.memory_limit,
                        at: now,
                        seen: now,
                    },
                );
                delta
            }
        };
        let t = self.totals.entry(o.tenant.clone()).or_default();
        *t = add(t, &delta);
        true
    }

    /// Writes a sandbox's last record and forgets it.
    fn finish(&mut self, id: SandboxId, now_ms: u64, end: &str) {
        if end != "lost" {
            self.free.remove(&id);
        }
        let mut lost = None;
        if let Some(t) = self.tracks.remove(&id) {
            let delta = t.pending;
            self.record(Kind::Final, now_ms, &id, &t, delta, Some(end));
            if end == "lost" {
                lost = Some(Lost {
                    tenant: t.tenant,
                    node: t.node,
                    template: t.template,
                    total: t.total,
                    at: t.at,
                });
            }
        }
        self.close(id);
        // After `close`, which may have dropped the oldest closed one.
        match lost {
            Some(l) if self.closed.contains(&id) => {
                self.lost.insert(id, l);
            }
            _ => {
                self.lost.remove(&id);
            }
        }
    }

    /// Once a second: starts a new period when one began (the old one's
    /// pending usage is recorded in it, and every sandbox's counters and
    /// every delete still to do are carried into the new one), and records
    /// what running sandboxes used when `flush` (every `interval`).
    pub fn tick(&mut self, now_ms: u64, flush: bool, deletes: &[(SandboxId, String, String)]) {
        let start = self.period.start_of(now_ms / 1000);
        // Ingress of a sandbox its node never reported (it ended before
        // the next probe): recorded on its own.
        let stale: Vec<SandboxId> = self
            .early
            .iter()
            .filter(|(_, e)| e.since.elapsed() >= LOST_AFTER)
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            if let Some(e) = self.early.remove(&id) {
                self.late(now_ms, &id, &e.tenant, &e.node, &e.template, e.counted);
            }
        }
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
        if self.period.start_of(now_ms / 1000) != self.start {
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
        let start = self.period.start_of(now_ms / 1000);
        self.period.next(start).saturating_sub(now_ms / 1000).max(1)
    }

    /// Ingress bytes the API relayed for sandbox `id` (of `tenant`, on
    /// `node`): `received` delivered to it, `sent` from it. Counted for
    /// the tenant at once; added to the sandbox's counters and its next
    /// record (or, when it has ended, a `late` record). Not counted for a
    /// sandbox that was deleted, or that the meter knows with another
    /// tenant or node.
    #[allow(clippy::too_many_arguments)]
    pub fn ingress(
        &mut self,
        now_ms: u64,
        id: &SandboxId,
        tenant: &str,
        node: &str,
        template: &str,
        received: u64,
        sent: u64,
    ) {
        if !self.tenants.contains(tenant) || self.free.contains(id) || received + sent == 0 {
            return;
        }
        let delta = Counters {
            ingress_received_bytes: received.min(MAX_COUNTER),
            ingress_sent_bytes: sent.min(MAX_COUNTER),
            ..Counters::default()
        };
        if let Some(t) = self.tracks.get_mut(id) {
            if t.tenant != tenant || t.node != node {
                self.odd += 1;
                return;
            }
            t.total = add(&t.total, &delta);
            t.pending = add(&t.pending, &delta);
        } else if self.closed.contains(id) {
            self.late(now_ms, id, tenant, node, template, delta);
            return;
        } else {
            let full = self.early.len() >= MAX_TRACKS;
            match self.early.get_mut(id) {
                Some(e) if e.tenant == tenant && e.node == node => {
                    e.counted = add(&e.counted, &delta);
                }
                Some(_) => {
                    self.odd += 1;
                    return;
                }
                None if full => {
                    self.late(now_ms, id, tenant, node, template, delta);
                    return;
                }
                None => {
                    self.early.insert(
                        *id,
                        Early {
                            tenant: tenant.to_string(),
                            node: node.to_string(),
                            template: template.to_string(),
                            counted: delta,
                            since: Instant::now(),
                        },
                    );
                }
            }
        }
        let t = self.totals.entry(tenant.to_string()).or_default();
        *t = add(t, &delta);
    }

    /// A `late` record of `delta` (added to the tenant's totals here).
    fn late(
        &mut self,
        now_ms: u64,
        id: &SandboxId,
        tenant: &str,
        node: &str,
        template: &str,
        delta: Counters,
    ) {
        let t = self.totals.entry(tenant.to_string()).or_default();
        *t = add(t, &delta);
        let track = Track {
            tenant: tenant.to_string(),
            node: node.to_string(),
            template: template.to_string(),
            total: delta,
            pending: Counters::default(),
            memory_bytes: 0,
            memory_limit: 0,
            at: Instant::now(),
            seen: Instant::now(),
        };
        self.record(Kind::Late, now_ms, id, &track, delta, None);
    }

    /// The ingress counted so far for sandbox `id`: (received, sent).
    pub fn ingress_of(&self, id: &SandboxId) -> (u64, u64) {
        let c = match (self.tracks.get(id), self.early.get(id)) {
            (Some(t), _) => t.total,
            (None, Some(e)) => e.counted,
            (None, None) => Counters::default(),
        };
        (c.ingress_received_bytes, c.ingress_sent_bytes)
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
            ..Counters::default()
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
    fn calendar_months() {
        let m = Periods::Months;
        // 2026-11-18 is in November 2026.
        let nov = 1_793_491_200; // 2026-11-01T00:00:00Z
        assert_eq!(utc_stamp(nov), "20261101T000000Z");
        assert_eq!(m.start_of(T0 / 1000), nov);
        assert_eq!(m.start_of(nov), nov);
        assert_eq!(m.start_of(nov - 1), m.previous(nov).unwrap());
        assert_eq!(utc_stamp(m.previous(nov).unwrap()), "20261001T000000Z");
        let dec = m.next(nov);
        assert_eq!(utc_stamp(dec), "20261201T000000Z");
        assert_eq!(dec - nov, 30 * 86400);
        // Over the year's end, and February in leap and common years.
        assert_eq!(utc_stamp(m.next(dec)), "20270101T000000Z");
        assert_eq!(
            utc_stamp(m.previous(m.next(dec)).unwrap()),
            "20261201T000000Z"
        );
        let feb_2028 = m.start_of(1_833_000_000); // 2028-02-01..
        assert_eq!(utc_stamp(feb_2028), "20280201T000000Z");
        assert_eq!(m.next(feb_2028) - feb_2028, 29 * 86400);
        let feb_2027 = m.previous(m.start_of(1_806_000_000)); // March 2027
        assert_eq!(utc_stamp(feb_2027.unwrap()), "20270201T000000Z");
        assert_eq!(m.next(feb_2027.unwrap()) - feb_2027.unwrap(), 28 * 86400);
        assert_eq!(m.start_of(0), 0);
        assert_eq!(m.previous(0), None);
        let p = period_view(nov, m);
        assert_eq!(
            (p.start, p.end, p.seconds),
            (nov * 1000, dec * 1000, 30 * 86400)
        );
        // A meter of months: the period, its end and the roll-over.
        let now = Instant::now();
        let mut meter = Meter::new(
            m,
            T0,
            now,
            true,
            86_400_000,
            vec!["a".into()],
            &Rebuilt::default(),
        );
        assert_eq!(meter.period().start, nov * 1000);
        assert_eq!(meter.seconds_left(T0), dec - T0 / 1000);
        let x = SandboxId::random().unwrap();
        meter.observe(
            "n1",
            T0,
            now,
            &BOUNDS,
            vec![observed(x, "a", usage(1000, 10, 0), T0 - 1000)],
            vec![],
            1,
            0,
            true,
        );
        assert_eq!(meter.totals("a", T0).cpu_ms, 10);
        meter.tick(dec * 1000 + 5, false, &[]);
        assert_eq!(meter.period().start, dec * 1000);
        assert_eq!(meter.totals("a", dec * 1000 + 5), Counters::default());
        let recs = records(&mut meter);
        assert_eq!(recs.last().unwrap().kind, Kind::Carry);
        assert_eq!(recs.last().unwrap().period, dec);
    }

    /// Once a delete is accepted for a sandbox of an unreachable node, what
    /// it uses is not charged: not when its node reports it again, not in
    /// its final record, not after a restart that rebuilds from the log.
    #[test]
    fn a_deleted_sandbox_is_charged_nothing_more() {
        let now = Instant::now();
        let mut m = meter(T0 + 1000, now, true);
        let x = SandboxId::random().unwrap();
        let see = |m: &mut Meter, at_ms: u64, at: Instant, live, ended| {
            m.observe("n1", at_ms, at, &BOUNDS, live, ended, 7, 0, true);
        };
        let t1 = now + Duration::from_secs(1);
        see(
            &mut m,
            T0 + 2000,
            t1,
            vec![observed(x, "a", usage(2000, 500, 10), T0)],
            vec![],
        );
        assert_eq!(m.totals("a", T0 + 2000).cpu_ms, 500);
        // The node stops answering; the tenant deletes the sandbox.
        m.note_delete(T0 + 3000, &x, "a", "n1", false);
        // Its node is back and reports what it did meanwhile: not charged.
        let t2 = now + Duration::from_secs(20);
        see(
            &mut m,
            T0 + 21_000,
            t2,
            vec![observed(x, "a", usage(21_000, 9000, 900), T0)],
            vec![],
        );
        assert_eq!(m.totals("a", T0 + 21_000).cpu_ms, 500);
        assert_eq!(m.totals("a", T0 + 21_000).egress_sent_bytes, 10);
        // Ingress to it is not charged either.
        m.ingress(T0 + 21_000, &x, "a", "n1", "python", 100, 100);
        assert_eq!(m.totals("a", T0 + 21_000).ingress_received_bytes, 0);
        m.note_delete(T0 + 22_000, &x, "a", "n1", true);
        // A restart between the delete being done and its final report
        // still knows it is not to be charged.
        let lines: Vec<String> = m.take_lines().into_iter().map(|l| l.text).collect();
        let mut rebuilt = Rebuilt::default();
        for l in &lines {
            rebuilt.take(l, true, &|t| t == "a");
        }
        assert!(rebuilt.freed.contains(&x));
        assert!(rebuilt.deletes.is_empty());
        let mut m2 = Meter::new(
            3600,
            T0 + 23_000,
            t2,
            true,
            86_400_000,
            vec!["a".into(), "b".into()],
            &rebuilt,
        );
        assert_eq!(m2.totals("a", T0 + 23_000).cpu_ms, 500);
        let t3 = now + Duration::from_secs(25);
        let mut end = observed(x, "a", usage(24_000, 9900, 950), T0);
        end.memory_bytes = 0;
        m2.observe(
            "n1",
            T0 + 25_000,
            t3,
            &BOUNDS,
            vec![],
            vec![end],
            7,
            1,
            true,
        );
        assert_eq!(m2.totals("a", T0 + 25_000).cpu_ms, 500);
        let recs = records(&mut m2);
        let fin = recs.iter().find(|r| r.kind == Kind::Final).unwrap();
        assert_eq!(fin.delta, Counters::default());
        assert_eq!(m2.tracked(), 0);
        // Without a sample after the restart either: a sandbox first seen
        // while freed is not charged.
        let y = SandboxId::random().unwrap();
        let mut rebuilt = Rebuilt::default();
        rebuilt.freed.insert(y);
        let mut m3 = Meter::new(
            3600,
            T0 + 1000,
            now,
            true,
            86_400_000,
            vec!["a".into()],
            &rebuilt,
        );
        see(
            &mut m3,
            T0 + 2000,
            t1,
            vec![observed(y, "a", usage(2000, 700, 0), T0 + 500)],
            vec![],
        );
        assert_eq!(m3.totals("a", T0 + 2000).cpu_ms, 0);
    }

    /// Ingress bytes count for the tenant at once, join the sandbox's
    /// counters and records, wait for a sandbox not reported yet, and go
    /// to `late` records for one that ended.
    #[test]
    fn ingress_is_counted() {
        let now = Instant::now();
        let mut m = meter(T0 + 1000, now, true);
        let (x, y) = (SandboxId::random().unwrap(), SandboxId::random().unwrap());
        // y is used before its node reported it.
        m.ingress(T0 + 1000, &y, "a", "n1", "python", 10, 20);
        assert_eq!(m.ingress_of(&y), (10, 20));
        let t = m.totals("a", T0 + 1000);
        assert_eq!((t.ingress_received_bytes, t.ingress_sent_bytes), (10, 20));
        let t1 = now + Duration::from_secs(1);
        m.observe(
            "n1",
            T0 + 2000,
            t1,
            &BOUNDS,
            vec![
                observed(x, "a", usage(1000, 10, 0), T0 + 500),
                observed(y, "a", usage(1000, 10, 0), T0 + 500),
            ],
            vec![],
            7,
            0,
            true,
        );
        m.ingress(T0 + 2000, &x, "a", "n1", "python", 1000, 5000);
        // Another tenant's name or another node: not counted.
        m.ingress(T0 + 2000, &x, "b", "n1", "python", 1, 1);
        m.ingress(T0 + 2000, &x, "a", "n2", "python", 1, 1);
        assert_eq!(m.ingress_of(&x), (1000, 5000));
        assert_eq!(m.ingress_of(&y), (10, 20));
        // A node never takes ingress counters away (it reports none).
        let t2 = now + Duration::from_secs(3);
        m.observe(
            "n1",
            T0 + 4000,
            t2,
            &BOUNDS,
            vec![
                observed(x, "a", usage(3000, 20, 0), T0 + 500),
                observed(y, "a", usage(3000, 20, 0), T0 + 500),
            ],
            vec![],
            7,
            0,
            true,
        );
        assert_eq!(m.ingress_of(&x), (1000, 5000));
        assert_eq!(m.odd, 2);
        m.tick(T0 + 4000, true, &[]);
        let recs = records(&mut m);
        let of = |id: SandboxId| {
            recs.iter()
                .filter(|r| r.sandbox == id.to_string())
                .fold(Counters::default(), |c, r| add(&c, &r.delta))
        };
        assert_eq!(of(x).ingress_sent_bytes, 5000);
        assert_eq!(of(y).ingress_received_bytes, 10);
        // Ended: the next bytes are a `late` record, in the totals.
        let mut end = observed(x, "a", usage(4000, 30, 0), T0 + 500);
        end.memory_bytes = 0;
        m.observe("n1", T0 + 5000, t2, &BOUNDS, vec![], vec![end], 7, 1, true);
        m.ingress(T0 + 6000, &x, "a", "n1", "python", 0, 7);
        let late = records(&mut m)
            .into_iter()
            .find(|r| r.kind == Kind::Late)
            .unwrap();
        assert_eq!(late.delta.ingress_sent_bytes, 7);
        let t = m.totals("a", T0 + 6000);
        assert_eq!(
            (t.ingress_received_bytes, t.ingress_sent_bytes),
            (1010, 5027)
        );
        // A rebuild counts the late record in the totals.
        let mut rebuilt = Rebuilt::default();
        rebuilt.take(&serde_json::to_string(&late).unwrap(), true, &|t| t == "a");
        assert_eq!(rebuilt.totals["a"].ingress_sent_bytes, 7);
        assert!(rebuilt.baselines.is_empty() && rebuilt.closed.is_empty());
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
    fn a_first_sample_is_bounded_by_the_time_counted() {
        let now = Instant::now();
        // The meter counts from T0 (the period's start); it is T0 + 2 s.
        let mut m = meter(T0 + 2000, now, true);
        let x = SandboxId::random().unwrap();
        // A node claims a week of run time and CPU for a sandbox made
        // just now: counted up to what 2 s (and the slack) allow.
        let week = 7 * 86_400_000;
        let claim = Counters {
            run_ms: week,
            cpu_ms: week * 4,
            ..Counters::default()
        };
        m.observe(
            "n1",
            T0 + 2000,
            now,
            &BOUNDS,
            vec![observed(x, "a", claim, T0 + 1000)],
            vec![],
            7,
            0,
            true,
        );
        let t = m.totals("a", T0 + 2000);
        assert_eq!(t.run_ms, 2000 + SLACK_MS);
        assert_eq!(t.cpu_ms, (2000 + SLACK_MS) * 4);
        assert_eq!(m.odd, 1);
    }

    #[test]
    fn a_lost_sandbox_that_is_reported_again_is_counted_on() {
        let now = Instant::now();
        let mut m = meter(T0 + 1000, now, true);
        let x = SandboxId::random().unwrap();
        let see = |m: &mut Meter, at_ms: u64, at: Instant, live: Vec<Observed>| {
            m.observe("n1", at_ms, at, &BOUNDS, live, vec![], 7, 0, true);
        };
        see(
            &mut m,
            T0 + 1000,
            now,
            vec![observed(x, "a", usage(1000, 100, 0), T0)],
        );
        // Its node leaves it out for more than a minute: closed as lost.
        let later = now + LOST_AFTER + Duration::from_secs(1);
        see(&mut m, T0 + 62_000, later, vec![]);
        let recs = records(&mut m);
        assert_eq!(recs.last().unwrap().end.as_deref(), Some("lost"));
        assert_eq!(m.tracked(), 0);
        // And then reports it again: counted from where it stood, once.
        let back = later + Duration::from_secs(2);
        see(
            &mut m,
            T0 + 64_000,
            back,
            vec![observed(x, "a", usage(64_000, 900, 0), T0)],
        );
        assert_eq!(m.tracked(), 1);
        assert_eq!(m.totals("a", T0 + 64_000).cpu_ms, 900);
        // Not under another tenant's name, nor from another node.
        let y = SandboxId::random().unwrap();
        see(
            &mut m,
            T0 + 64_000,
            back,
            vec![
                observed(x, "a", usage(64_000, 900, 0), T0),
                observed(y, "a", usage(1000, 50, 0), T0),
            ],
        );
        let gone = back + LOST_AFTER + Duration::from_secs(1);
        see(
            &mut m,
            T0 + 130_000,
            gone,
            vec![observed(x, "a", usage(130_000, 900, 0), T0)],
        );
        m.observe(
            "n2",
            T0 + 131_000,
            gone,
            &BOUNDS,
            vec![observed(y, "a", usage(131_000, 5000, 0), T0)],
            vec![],
            9,
            0,
            true,
        );
        see(
            &mut m,
            T0 + 131_000,
            gone,
            vec![
                observed(x, "a", usage(131_000, 900, 0), T0),
                observed(y, "b", usage(131_000, 5000, 0), T0),
            ],
        );
        assert_eq!(m.totals("a", T0 + 131_000).cpu_ms, 950);
        assert_eq!(m.totals("b", T0 + 131_000).cpu_ms, 0);
        // The log says the same after a restart: lost, with its counters.
        let mut rebuilt = Rebuilt::default();
        let known = |t: &str| t == "a" || t == "b";
        let mut m2 = meter(T0 + 1000, now, true);
        see(
            &mut m2,
            T0 + 1000,
            now,
            vec![observed(x, "a", usage(1000, 100, 0), T0)],
        );
        see(&mut m2, T0 + 62_000, later, vec![]);
        for line in m2.take_lines() {
            rebuilt.take(&line.text, true, &known);
        }
        assert!(rebuilt.closed.contains(&x) && rebuilt.lost.contains_key(&x));
        let mut m3 = Meter::new(
            3600,
            T0 + 63_000,
            later,
            true,
            86_400_000,
            vec!["a".into(), "b".into()],
            &rebuilt,
        );
        see(
            &mut m3,
            T0 + 64_000,
            back,
            vec![observed(x, "a", usage(64_000, 900, 0), T0)],
        );
        assert_eq!(m3.totals("a", T0 + 64_000).cpu_ms, 900);
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
        assert_eq!(rebuilt.closed, HashSet::from([y]));
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
