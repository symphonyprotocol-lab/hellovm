//! `hellovm-api`: the public API of hellovm. It authenticates tenants by
//! bearer token, enforces each tenant's limit on concurrent sandboxes,
//! places new sandboxes on a node, keeps the sandbox metadata
//! ([`store`]), and passes each request about a sandbox to the node that
//! runs it (`hellovm-noded`), after checking that the sandbox is the
//! caller's. See the README, "Control plane".

pub mod config;
pub mod service;
pub mod store;
