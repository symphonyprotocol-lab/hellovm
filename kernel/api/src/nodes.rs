//! What the API knows of each node: whether it answers (its health, with
//! hysteresis), its last reported load and templates, and the sandboxes
//! this API placed on it since; and the placement rule that picks a node
//! for a new sandbox from that.
//!
//! A node is *healthy* (it answers and takes sandboxes), *draining* (it
//! answers but takes no new sandboxes; it says so itself) or
//! *unreachable* (`unhealthy_after` probes in a row got no answer or
//! nonsense, or as many connections for requests in a row could not be
//! made; it comes back after `healthy_after` good probes in a row). Before
//! the first probe a node is *unknown* and gets nothing.
//!
//! A request that was sent and got no answer in time says nothing of the
//! node: how long a request takes is partly up to the sandbox it is for,
//! so counting it would let one tenant make a node unreachable for all.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Instant, SystemTime};

use hellovm_control::types::NodeStatus;
use serde::Serialize;

use crate::config::{valid_name, Node};

/// Whether a node answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reach {
    /// Not asked yet.
    Unknown,
    Up,
    Down,
}

#[derive(Clone, Copy, Debug)]
pub struct HealthPolicy {
    /// Failures in a row that make a node unreachable.
    pub unhealthy_after: u32,
    /// Good probes in a row that make an unreachable node healthy again.
    pub healthy_after: u32,
}

/// The health state machine of one node. Failed probes (the periodic
/// reconciliation) and connections for requests that could not be made
/// are counted, each kind on its own; only probes bring a node back.
#[derive(Clone, Debug)]
pub struct Health {
    pub reach: Reach,
    /// Failed probes in a row (while up). Answered requests do not reset
    /// it: a node whose status cannot be had is not known, whatever else
    /// it answers.
    probe_failures: u32,
    /// Connections for requests that could not be made, in a row (while
    /// up).
    connect_failures: u32,
    /// Good probes in a row (while down).
    successes: u32,
    /// When `reach` last changed.
    pub since: SystemTime,
    pub last_error: Option<String>,
}

impl Default for Health {
    fn default() -> Health {
        Health {
            reach: Reach::Unknown,
            probe_failures: 0,
            connect_failures: 0,
            successes: 0,
            since: SystemTime::now(),
            last_error: None,
        }
    }
}

impl Health {
    fn set(&mut self, reach: Reach) -> Option<(Reach, Reach)> {
        let before = self.reach;
        self.reach = reach;
        self.probe_failures = 0;
        self.connect_failures = 0;
        self.successes = 0;
        self.since = SystemTime::now();
        Some((before, reach))
    }

    /// A probe got a valid answer. Returns the change of reach, if any.
    pub fn probe_ok(&mut self, policy: &HealthPolicy) -> Option<(Reach, Reach)> {
        match self.reach {
            // The first answer decides at once: nothing to smooth yet.
            Reach::Unknown => self.set(Reach::Up),
            Reach::Up => {
                self.probe_failures = 0;
                self.connect_failures = 0;
                None
            }
            Reach::Down => {
                self.successes += 1;
                if self.successes >= policy.healthy_after {
                    self.set(Reach::Up)
                } else {
                    None
                }
            }
        }
    }

    fn note(&mut self, why: &str) {
        self.last_error = Some(why.chars().take(256).collect());
    }

    /// A probe failed: no connection, no answer in time, or an answer that
    /// is not what a node sends.
    pub fn probe_failed(&mut self, policy: &HealthPolicy, why: &str) -> Option<(Reach, Reach)> {
        self.note(why);
        match self.reach {
            Reach::Unknown => self.set(Reach::Down),
            Reach::Up => {
                self.probe_failures += 1;
                if self.probe_failures >= policy.unhealthy_after {
                    self.set(Reach::Down)
                } else {
                    None
                }
            }
            Reach::Down => {
                self.successes = 0;
                None
            }
        }
    }

    /// No connection could be made for a request. It counts while the node
    /// is up only: a request that began before the node went down says
    /// nothing of the probes since.
    pub fn connect_failed(&mut self, policy: &HealthPolicy, why: &str) -> Option<(Reach, Reach)> {
        if self.reach != Reach::Up {
            return None;
        }
        self.note(why);
        self.connect_failures += 1;
        if self.connect_failures >= policy.unhealthy_after {
            self.set(Reach::Down)
        } else {
            None
        }
    }

    /// A request was answered: connections can be made (a node that is
    /// down comes back by probes only).
    pub fn answered(&mut self) {
        self.connect_failures = 0;
    }
}

/// The state shown to operators and logged.
pub fn state_name(reach: Reach, draining: bool) -> &'static str {
    match reach {
        Reach::Unknown => "unknown",
        Reach::Down => "unreachable",
        Reach::Up if draining => "draining",
        Reach::Up => "healthy",
    }
}

/// One template on a node, as the API keeps it.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Template {
    pub name: String,
    pub ready: bool,
    /// The one tenant it serves, if not shared.
    pub tenant: Option<String>,
    /// The memory limit of each of its sandboxes, in bytes.
    pub memory_limit_bytes: Option<u64>,
}

/// A node's report, checked.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Load {
    pub sandboxes: usize,
    pub creating: usize,
    pub max_sandboxes: usize,
    pub memory_bytes: u64,
    pub memory_limit_bytes: u64,
    pub draining: bool,
    /// Its CPUs (what a node that does not say is taken to have:
    /// [`MAX_CPUS`]).
    pub cpus: u32,
    pub templates: Vec<Template>,
}

/// Most CPUs a node may report.
pub const MAX_CPUS: u32 = 65536;
/// Largest memory limit of a sandbox a node may report (1 PiB).
pub const MAX_SANDBOX_MEMORY: u64 = 1 << 50;

/// Most templates a node may report.
pub const MAX_TEMPLATES: usize = 256;
/// Most sandboxes a node may have (`noded`'s own bound).
pub const MAX_NODE_SANDBOXES: usize = 4096;

/// Checks a node's status: it must be the node it should be, and every
/// field within what a node can report.
pub fn check_status(status: NodeStatus, name: &str) -> Result<Load, String> {
    if status.node != name {
        return Err("the node reports another name".into());
    }
    if status.templates.len() > MAX_TEMPLATES {
        return Err("too many templates".into());
    }
    if !(1..=MAX_NODE_SANDBOXES).contains(&status.max_sandboxes)
        || status.sandboxes > MAX_NODE_SANDBOXES
        || status.creating > MAX_NODE_SANDBOXES
    {
        return Err("sandbox counts out of range".into());
    }
    if status.memory_limit_bytes == 0 {
        return Err("no memory limit".into());
    }
    if status.cpus > MAX_CPUS {
        return Err("too many CPUs".into());
    }
    let mut templates: Vec<Template> = Vec::with_capacity(status.templates.len());
    for t in status.templates {
        if !valid_name(&t.name)
            || t.tenant.as_deref().is_some_and(|t| !valid_name(t))
            || templates.iter().any(|o| o.name == t.name)
            || t.memory_limit_bytes
                .is_some_and(|m| m == 0 || m > MAX_SANDBOX_MEMORY)
        {
            return Err("a malformed template".into());
        }
        templates.push(Template {
            name: t.name,
            ready: t.ready,
            tenant: t.tenant,
            memory_limit_bytes: t.memory_limit_bytes,
        });
    }
    Ok(Load {
        sandboxes: status.sandboxes,
        creating: status.creating,
        max_sandboxes: status.max_sandboxes,
        memory_bytes: status.memory_bytes,
        memory_limit_bytes: status.memory_limit_bytes,
        draining: status.draining,
        cpus: if status.cpus == 0 {
            MAX_CPUS
        } else {
            status.cpus
        },
        templates,
    })
}

impl Load {
    /// The template `name` as `tenant` may use it.
    fn template(&self, name: &str, tenant: &str) -> Option<&Template> {
        self.templates
            .iter()
            .find(|t| t.name == name && t.tenant.as_deref().is_none_or(|only| only == tenant))
    }
}

/// A small pseudo-random generator (xorshift64*) for tie-breaks: nothing
/// secret depends on it.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }

    pub fn seeded() -> Rng {
        let mut bytes = [0u8; 8];
        if hellovm_control::ids::random_bytes(&mut bytes).is_err() {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default();
            bytes = (now.as_nanos() as u64).to_le_bytes();
        }
        Rng::new(u64::from_le_bytes(bytes))
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A number below `n` (`n` > 0).
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// The placement rule, apart from the bookkeeping so it can be tested.
pub mod placement {
    use super::{Load, Rng};

    /// A node that could take a sandbox.
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub struct Candidate {
        pub node: usize,
        /// See [`load`].
        pub load: f64,
        /// By what is known, it has the template ready and room.
        pub fits: bool,
    }

    /// How loaded a node is, 0 (empty) to 1 (full) or more: the larger of
    /// its sandboxes over `max_sandboxes` and its memory in use over its
    /// limit. `extra` are sandboxes it does not report yet (placed since its
    /// last report, or being placed).
    pub fn load(load: &Load, extra: usize) -> f64 {
        let count = load
            .sandboxes
            .saturating_add(load.creating)
            .saturating_add(extra);
        let by_count = count as f64 / load.max_sandboxes.max(1) as f64;
        let by_memory = load.memory_bytes as f64 / load.memory_limit_bytes.max(1) as f64;
        by_count.max(by_memory)
    }

    /// Whether a node has room for one more by what is known.
    pub fn has_room(load: &Load, extra: usize) -> bool {
        load.sandboxes
            .saturating_add(load.creating)
            .saturating_add(extra)
            < load.max_sandboxes
            && load.memory_bytes < load.memory_limit_bytes
    }

    /// The order to try the candidates in: those that fit before those
    /// that do not (whose report may be stale: the node decides), each
    /// group by load, lowest first, nodes of the same load in random order.
    pub fn order(mut candidates: Vec<Candidate>, rng: &mut Rng) -> Vec<usize> {
        // Shuffle, then a stable sort: equal keys keep the random order.
        for i in (1..candidates.len()).rev() {
            let j = rng.below(i + 1);
            candidates.swap(i, j);
        }
        candidates.sort_by(|a, b| b.fits.cmp(&a.fits).then(a.load.total_cmp(&b.load)));
        candidates.into_iter().map(|c| c.node).collect()
    }
}

/// Why no node can be asked to make a sandbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoPlace {
    /// Every node reported, and none has the template (for this tenant).
    UnknownTemplate,
    /// Known, but ready on no node that takes sandboxes.
    NotReady,
    /// No node that takes sandboxes has room (or none is left to try, or
    /// the only nodes that might have the template never reported).
    Full,
}

struct State {
    health: Health,
    load: Option<Load>,
    /// When the probe that brought `load` was sent.
    reported_at: Option<Instant>,
    /// Sandboxes this API placed on the node that its report may not count
    /// yet: when each was placed.
    placed: VecDeque<Instant>,
    /// Creations being asked of it now.
    in_flight: usize,
}

impl State {
    fn draining(&self) -> bool {
        self.load.as_ref().is_some_and(|l| l.draining)
    }

    fn state(&self) -> &'static str {
        state_name(self.health.reach, self.draining())
    }
}

/// Most placements remembered per node between two reports.
const MAX_PLACED: usize = 1 << 16;

/// What an operator sees of a node.
#[derive(Serialize)]
pub struct NodeView {
    pub name: String,
    pub addr: String,
    /// `healthy`, `draining`, `unreachable` or `unknown`.
    pub state: &'static str,
    /// When it last became reachable or unreachable (Unix ms).
    pub since: u64,
    pub last_error: Option<String>,
    /// How long ago its last report was asked for (ms).
    pub reported_ms_ago: Option<u64>,
    /// Sandboxes placed on it by this API that its report does not count
    /// yet, and creations in flight.
    pub placed_since_report: usize,
    pub in_flight: usize,
    /// Its last report.
    pub report: Option<Load>,
}

/// Every configured node and what is known of it.
pub struct Nodes {
    configs: Vec<Node>,
    policy: HealthPolicy,
    inner: Mutex<(Vec<State>, Rng)>,
}

impl Nodes {
    pub fn new(configs: Vec<Node>, policy: HealthPolicy) -> Nodes {
        let states = configs
            .iter()
            .map(|_| State {
                health: Health::default(),
                load: None,
                reported_at: None,
                placed: VecDeque::new(),
                in_flight: 0,
            })
            .collect();
        Nodes {
            configs,
            policy,
            inner: Mutex::new((states, Rng::seeded())),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, (Vec<State>, Rng)> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn configs(&self) -> &[Node] {
        &self.configs
    }

    pub fn index(&self, name: &str) -> Option<usize> {
        self.configs.iter().position(|n| n.name == name)
    }

    fn log_change(&self, i: usize, before: &'static str, state: &State) {
        let after = state.state();
        if before != after {
            let error = match (&state.health.last_error, state.health.reach) {
                (Some(e), Reach::Down) => format!(" error={e:?}"),
                _ => String::new(),
            };
            log::info!(
                "node state change: node={} from={before} to={after}{error}",
                self.configs[i].name
            );
        }
    }

    /// Node `i` gave this report to a question asked at `asked`: to a
    /// probe (`probe`, which counts for its health) or to an operator's
    /// request. A report older than the one kept (two questions answered
    /// out of order) does not replace it.
    pub fn reported(&self, i: usize, asked: Instant, load: Load, probe: bool) {
        let mut inner = self.lock();
        let state = &mut inner.0[i];
        let before = state.state();
        if probe {
            state.health.probe_ok(&self.policy);
        }
        if state.reported_at.is_none_or(|at| asked >= at) {
            // Placements made before the question are in the report.
            state.placed.retain(|at| *at >= asked);
            state.load = Some(load);
            state.reported_at = Some(asked);
        }
        self.log_change(i, before, state);
    }

    /// A probe of node `i` failed, or it answered a request with what no
    /// node sends.
    pub fn failed(&self, i: usize, why: &str) {
        let mut inner = self.lock();
        let state = &mut inner.0[i];
        let before = state.state();
        state.health.probe_failed(&self.policy, why);
        self.log_change(i, before, state);
    }

    /// No connection to node `i` could be made for a request.
    pub fn connect_failed(&self, i: usize, why: &str) {
        let mut inner = self.lock();
        let state = &mut inner.0[i];
        let before = state.state();
        state.health.connect_failed(&self.policy, why);
        self.log_change(i, before, state);
    }

    /// A request to node `i` was answered.
    pub fn answered(&self, i: usize) {
        self.lock().0[i].health.answered();
    }

    /// Whether requests may be sent to node `i` (it is not unreachable).
    pub fn reachable(&self, i: usize) -> bool {
        self.lock().0[i].health.reach == Reach::Up
    }

    /// Picks a node for a sandbox of `template` for `tenant`, not one of
    /// `tried`, and counts the creation as in flight there until
    /// [`Nodes::done`].
    pub fn place(&self, template: &str, tenant: &str, tried: &[usize]) -> Result<usize, NoPlace> {
        let mut inner = self.lock();
        let (states, rng) = &mut *inner;
        let mut candidates = Vec::new();
        let mut known = false;
        let mut unreported = false;
        let mut ready_somewhere = false;
        for (i, state) in states.iter().enumerate() {
            let Some(load) = &state.load else {
                unreported = true;
                continue;
            };
            let Some(t) = load.template(template, tenant) else {
                continue;
            };
            known = true;
            if state.health.reach != Reach::Up || load.draining {
                continue;
            }
            ready_somewhere |= t.ready;
            if tried.contains(&i) {
                continue;
            }
            let extra = state.placed.len() + state.in_flight;
            candidates.push(placement::Candidate {
                node: i,
                load: placement::load(load, extra),
                fits: t.ready && placement::has_room(load, extra),
            });
        }
        let Some(&chosen) = placement::order(candidates, rng).first() else {
            // A node that never reported may have the template: only when
            // every node has is the template known not to exist.
            return Err(if !known && !unreported {
                NoPlace::UnknownTemplate
            } else if !known {
                NoPlace::Full
            } else if !ready_somewhere {
                NoPlace::NotReady
            } else {
                NoPlace::Full
            });
        };
        states[chosen].in_flight += 1;
        Ok(chosen)
    }

    /// The creation placed on node `i` ended; `made` if it made a sandbox.
    pub fn done(&self, i: usize, made: bool) {
        let mut inner = self.lock();
        let state = &mut inner.0[i];
        state.in_flight = state.in_flight.saturating_sub(1);
        if made {
            if state.placed.len() >= MAX_PLACED {
                state.placed.pop_front();
            }
            state.placed.push_back(Instant::now());
        }
    }

    /// The templates `tenant` may use, by name: each known on some node,
    /// ready if ready on a node that takes sandboxes now.
    pub fn templates(&self, tenant: &str) -> Vec<(String, bool)> {
        let inner = self.lock();
        let mut out: Vec<(String, bool)> = Vec::new();
        for state in &inner.0 {
            let Some(load) = &state.load else { continue };
            let usable = state.health.reach == Reach::Up && !load.draining;
            for t in &load.templates {
                if t.tenant.as_deref().is_some_and(|only| only != tenant) {
                    continue;
                }
                let ready = usable && t.ready;
                match out.iter_mut().find(|(name, _)| *name == t.name) {
                    Some((_, r)) => *r |= ready,
                    None => out.push((t.name.clone(), ready)),
                }
            }
        }
        out.sort();
        out
    }

    /// The memory limit of a sandbox of template `name` for `tenant`: the
    /// largest any node reported (the node that makes it is not known
    /// yet). `None` when no node said.
    pub fn template_memory(&self, name: &str, tenant: &str) -> Option<u64> {
        let inner = self.lock();
        inner
            .0
            .iter()
            .filter_map(|s| s.load.as_ref()?.template(name, tenant)?.memory_limit_bytes)
            .max()
    }

    /// What node `i` can report in a given time (by its last report).
    pub fn bounds(&self, i: usize) -> crate::meter::Bounds {
        let inner = self.lock();
        let load = inner.0[i].load.as_ref();
        crate::meter::Bounds {
            cpus: u64::from(load.map_or(MAX_CPUS, |l| l.cpus)),
            memory_bytes: load.map_or(u64::MAX, |l| l.memory_limit_bytes),
        }
    }

    pub fn view(&self, i: usize) -> NodeView {
        let inner = self.lock();
        let state = &inner.0[i];
        let since = state
            .health
            .since
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        NodeView {
            name: self.configs[i].name.clone(),
            addr: self.configs[i].addr.clone(),
            state: state.state(),
            since,
            last_error: state.health.last_error.clone(),
            reported_ms_ago: state.reported_at.map(|at| at.elapsed().as_millis() as u64),
            placed_since_report: state.placed.len(),
            in_flight: state.in_flight,
            report: state.load.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::placement::{self, Candidate};
    use super::*;

    const POLICY: HealthPolicy = HealthPolicy {
        unhealthy_after: 3,
        healthy_after: 2,
    };

    #[test]
    fn health_starts_with_the_first_answer() {
        let mut h = Health::default();
        assert_eq!(h.probe_ok(&POLICY), Some((Reach::Unknown, Reach::Up)));
        let mut h = Health::default();
        assert_eq!(
            h.probe_failed(&POLICY, "refused"),
            Some((Reach::Unknown, Reach::Down))
        );
        // A request decides nothing before the first probe.
        let mut h = Health::default();
        assert_eq!(h.connect_failed(&POLICY, "refused"), None);
        assert_eq!(h.reach, Reach::Unknown);
    }

    #[test]
    fn health_has_hysteresis() {
        let mut h = Health::default();
        h.probe_ok(&POLICY);
        // One or two slow answers do not flap it.
        assert_eq!(h.probe_failed(&POLICY, "slow"), None);
        assert_eq!(h.probe_failed(&POLICY, "slow"), None);
        assert_eq!(h.probe_ok(&POLICY), None);
        assert_eq!(h.probe_failed(&POLICY, "slow"), None);
        assert_eq!(h.probe_failed(&POLICY, "slow"), None);
        assert_eq!(h.reach, Reach::Up);
        // Three in a row do.
        assert_eq!(
            h.probe_failed(&POLICY, "gone"),
            Some((Reach::Up, Reach::Down))
        );
        assert_eq!(h.last_error.as_deref(), Some("gone"));
        // Back after two good probes in a row; a failed probe between
        // resets.
        assert_eq!(h.probe_ok(&POLICY), None);
        assert_eq!(h.probe_failed(&POLICY, "again"), None);
        assert_eq!(h.probe_ok(&POLICY), None);
        h.answered();
        assert_eq!(h.reach, Reach::Down, "requests do not bring it back");
        assert_eq!(h.probe_ok(&POLICY), Some((Reach::Down, Reach::Up)));
        // And the count starts afresh.
        assert_eq!(h.probe_failed(&POLICY, "x"), None);
        assert_eq!(h.probe_failed(&POLICY, "x"), None);
        assert_eq!(h.probe_failed(&POLICY, "x"), Some((Reach::Up, Reach::Down)));
    }

    #[test]
    fn answered_requests_do_not_hide_failing_probes() {
        let mut h = Health::default();
        h.probe_ok(&POLICY);
        assert_eq!(h.probe_failed(&POLICY, "no status"), None);
        h.answered();
        assert_eq!(h.probe_failed(&POLICY, "no status"), None);
        h.answered();
        assert_eq!(
            h.probe_failed(&POLICY, "no status"),
            Some((Reach::Up, Reach::Down))
        );
    }

    #[test]
    fn connections_that_fail_count_on_their_own() {
        let mut h = Health::default();
        h.probe_ok(&POLICY);
        // An answered request, or a good probe, resets them.
        assert_eq!(h.connect_failed(&POLICY, "refused"), None);
        assert_eq!(h.connect_failed(&POLICY, "refused"), None);
        h.answered();
        assert_eq!(h.connect_failed(&POLICY, "refused"), None);
        assert_eq!(h.connect_failed(&POLICY, "refused"), None);
        assert_eq!(h.probe_ok(&POLICY), None);
        // They do not add to failed probes.
        assert_eq!(h.probe_failed(&POLICY, "slow"), None);
        assert_eq!(h.connect_failed(&POLICY, "refused"), None);
        assert_eq!(h.connect_failed(&POLICY, "refused"), None);
        assert_eq!(h.reach, Reach::Up);
        assert_eq!(
            h.connect_failed(&POLICY, "refused"),
            Some((Reach::Up, Reach::Down))
        );
        // While down, a request left from before does not delay the way
        // back.
        assert_eq!(h.probe_ok(&POLICY), None);
        assert_eq!(h.connect_failed(&POLICY, "late"), None);
        assert_eq!(h.last_error.as_deref(), Some("refused"));
        assert_eq!(h.probe_ok(&POLICY), Some((Reach::Down, Reach::Up)));
    }

    #[test]
    fn state_names() {
        assert_eq!(state_name(Reach::Up, false), "healthy");
        assert_eq!(state_name(Reach::Up, true), "draining");
        assert_eq!(state_name(Reach::Down, true), "unreachable");
        assert_eq!(state_name(Reach::Unknown, false), "unknown");
    }

    fn load(sandboxes: usize, max: usize, memory: u64, limit: u64) -> Load {
        Load {
            sandboxes,
            creating: 0,
            max_sandboxes: max,
            memory_bytes: memory,
            memory_limit_bytes: limit,
            draining: false,
            cpus: 4,
            templates: vec![Template {
                name: "python".into(),
                ready: true,
                tenant: None,
                memory_limit_bytes: Some(100),
            }],
        }
    }

    #[test]
    fn load_is_the_larger_fraction() {
        assert_eq!(placement::load(&load(2, 8, 0, 100), 0), 0.25);
        assert_eq!(placement::load(&load(2, 8, 0, 100), 2), 0.5);
        assert_eq!(placement::load(&load(1, 8, 90, 100), 0), 0.9);
        assert!(placement::has_room(&load(7, 8, 0, 100), 0));
        assert!(!placement::has_room(&load(7, 8, 0, 100), 1));
        assert!(!placement::has_room(&load(0, 8, 100, 100), 0));
    }

    #[test]
    fn order_prefers_fitting_then_least_loaded() {
        let mut rng = Rng::new(7);
        let c = |node, load, fits| Candidate { node, load, fits };
        let order = placement::order(
            vec![
                c(0, 0.5, true),
                c(1, 0.1, false),
                c(2, 0.2, true),
                c(3, 0.0, false),
            ],
            &mut rng,
        );
        assert_eq!(order, vec![2, 0, 3, 1]);
        assert!(placement::order(Vec::new(), &mut rng).is_empty());
    }

    #[test]
    fn ties_are_broken_at_random() {
        let mut rng = Rng::new(42);
        let mut first = [0usize; 3];
        for _ in 0..3000 {
            let order = placement::order(
                (0..3)
                    .map(|node| Candidate {
                        node,
                        load: 0.25,
                        fits: true,
                    })
                    .collect(),
                &mut rng,
            );
            first[order[0]] += 1;
        }
        assert!(first.iter().all(|&n| n > 800), "{first:?}");
    }

    fn nodes(n: usize) -> Nodes {
        let configs = (0..n)
            .map(|i| Node {
                name: format!("n{i}"),
                addr: format!("127.0.0.1:{}", 1000 + i),
                token: "t".repeat(24),
            })
            .collect();
        Nodes::new(configs, POLICY)
    }

    #[test]
    fn concurrent_placements_spread_before_any_report() {
        let nodes = nodes(3);
        let asked = Instant::now();
        for i in 0..3 {
            nodes.reported(i, asked, load(0, 4, 0, 1 << 30), true);
        }
        // Six creations in flight at once: two per node, not six on one.
        let mut count = [0; 3];
        for _ in 0..6 {
            count[nodes.place("python", "acme", &[]).unwrap()] += 1;
        }
        assert_eq!(count, [2, 2, 2]);
        // Done ones still count until a report asked after them.
        for i in 0..3 {
            nodes.done(i, true);
            nodes.done(i, false);
        }
        assert_eq!(nodes.view(0).placed_since_report, 1);
        assert_eq!(nodes.view(0).in_flight, 0);
        let later = Instant::now();
        nodes.reported(0, later, load(1, 4, 0, 1 << 30), true);
        assert_eq!(nodes.view(0).placed_since_report, 0);
    }

    #[test]
    fn an_older_report_does_not_replace_a_newer_one() {
        let nodes = nodes(1);
        let early = Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let late = Instant::now();
        let mut draining = load(0, 4, 0, 100);
        draining.draining = true;
        nodes.reported(0, early, load(0, 4, 0, 100), true);
        // An operator drains it; a probe asked before that answers after.
        nodes.reported(0, late, draining, false);
        assert_eq!(nodes.view(0).state, "draining");
        nodes.reported(0, early, load(0, 4, 0, 100), true);
        assert_eq!(nodes.view(0).state, "draining");
    }

    #[test]
    fn an_operators_report_is_not_a_probe() {
        let nodes = nodes(1);
        nodes.reported(0, Instant::now(), load(0, 4, 0, 100), true);
        for _ in 0..3 {
            nodes.failed(0, "gone");
        }
        nodes.reported(0, Instant::now(), load(0, 4, 0, 100), false);
        nodes.reported(0, Instant::now(), load(0, 4, 0, 100), false);
        assert_eq!(nodes.view(0).state, "unreachable");
        nodes.reported(0, Instant::now(), load(0, 4, 0, 100), true);
        nodes.reported(0, Instant::now(), load(0, 4, 0, 100), true);
        assert_eq!(nodes.view(0).state, "healthy");
    }

    #[test]
    fn a_template_is_unknown_only_when_every_node_reported() {
        let nodes = nodes(2);
        nodes.reported(0, Instant::now(), load(0, 4, 0, 100), true);
        // The other node never answered: it may have the template.
        nodes.failed(1, "refused");
        assert_eq!(nodes.place("other", "acme", &[]), Err(NoPlace::Full));
        nodes.reported(1, Instant::now(), load(0, 4, 0, 100), true);
        assert_eq!(
            nodes.place("other", "acme", &[]),
            Err(NoPlace::UnknownTemplate)
        );
    }

    #[test]
    fn placement_skips_full_draining_down_and_foreign() {
        let nodes = nodes(4);
        let now = Instant::now();
        nodes.reported(0, now, load(4, 4, 0, 100), true); // full
        let mut draining = load(0, 4, 0, 100);
        draining.draining = true;
        nodes.reported(1, now, draining, true);
        nodes.reported(2, now, load(0, 4, 0, 100), true);
        for _ in 0..3 {
            nodes.failed(2, "refused");
        }
        assert_eq!(nodes.view(2).state, "unreachable");
        assert_eq!(nodes.view(1).state, "draining");
        let mut own = load(0, 4, 0, 100);
        own.templates[0].tenant = Some("beta".into());
        nodes.reported(3, now, own, true);
        // Only the full node is left: asked last (its report may be old).
        assert_eq!(nodes.place("python", "acme", &[]), Ok(0));
        assert_eq!(nodes.place("python", "acme", &[0]), Err(NoPlace::Full));
        assert_eq!(nodes.place("python", "beta", &[]), Ok(3));
        assert_eq!(
            nodes.place("other", "acme", &[]),
            Err(NoPlace::UnknownTemplate)
        );
        // Beta's own template is not acme's to see.
        assert_eq!(nodes.templates("acme"), vec![("python".to_string(), true)]);
    }

    #[test]
    fn templates_answer_the_same_across_nodes() {
        let nodes = nodes(3);
        let now = Instant::now();
        let mut a = load(0, 4, 0, 100);
        a.templates.push(Template {
            name: "extra".into(),
            ready: false,
            tenant: None,
            memory_limit_bytes: Some(300),
        });
        nodes.reported(0, now, a, true);
        let mut b = load(0, 4, 0, 100);
        b.templates[0].ready = false;
        nodes.reported(1, now, b, true);
        assert_eq!(
            nodes.templates("acme"),
            vec![("extra".to_string(), false), ("python".to_string(), true)]
        );
        assert_eq!(nodes.template_memory("extra", "acme"), Some(300));
        assert_eq!(nodes.template_memory("python", "acme"), Some(100));
        assert_eq!(nodes.template_memory("none", "acme"), None);
        assert_eq!(nodes.place("extra", "acme", &[]), Ok(0), "tried anyway");
        nodes.done(0, false);
        // Ready only on a node that went away: listed, not ready.
        for _ in 0..3 {
            nodes.failed(0, "gone");
        }
        assert_eq!(
            nodes.templates("acme"),
            vec![("extra".to_string(), false), ("python".to_string(), false)]
        );
        assert_eq!(nodes.place("extra", "acme", &[]), Err(NoPlace::NotReady));
        assert_eq!(nodes.place("python", "acme", &[]), Ok(1), "tried anyway");
    }

    fn status() -> NodeStatus {
        NodeStatus {
            node: "n0".into(),
            templates: Vec::new(),
            sandboxes: 0,
            creating: 0,
            max_sandboxes: 8,
            memory_bytes: 0,
            memory_limit_bytes: 1,
            draining: false,
            cpus: 4,
        }
    }

    #[test]
    fn reports_are_checked() {
        assert!(check_status(status(), "n0").is_ok());
        assert!(check_status(status(), "n1").is_err(), "another node");
        let mut s = status();
        s.max_sandboxes = 0;
        assert!(check_status(s, "n0").is_err());
        let mut s = status();
        s.sandboxes = usize::MAX;
        assert!(check_status(s, "n0").is_err());
        let mut s = status();
        s.memory_limit_bytes = 0;
        assert!(check_status(s, "n0").is_err());
        let t = |name: &str| hellovm_control::types::TemplateStatus {
            name: name.into(),
            ready: true,
            starts: 1,
            tenant: None,
            pid: None,
            memory_limit_bytes: Some(1 << 20),
        };
        let mut s = status();
        s.cpus = MAX_CPUS + 1;
        assert!(check_status(s, "n0").is_err());
        let mut s = status();
        s.cpus = 0;
        assert_eq!(check_status(s, "n0").unwrap().cpus, MAX_CPUS);
        let mut s = status();
        let mut huge = t("a");
        huge.memory_limit_bytes = Some(u64::MAX);
        s.templates = vec![huge];
        assert!(check_status(s, "n0").is_err());
        let mut s = status();
        s.templates = vec![t("../x")];
        assert!(check_status(s, "n0").is_err());
        let mut s = status();
        s.templates = vec![t("a"), t("a")];
        assert!(check_status(s, "n0").is_err());
        let mut s = status();
        s.templates = (0..=MAX_TEMPLATES).map(|i| t(&format!("t{i}"))).collect();
        assert!(check_status(s, "n0").is_err());
    }
}
