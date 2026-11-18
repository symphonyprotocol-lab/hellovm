//! The node API: what `hellovm-api` calls. Every request carries the
//! node's bearer token; requests about one sandbox also name its tenant
//! (`X-Hellovm-Tenant`), and a sandbox of another tenant is reported as
//! missing, so a mistake in the API cannot reach across tenants here.
//!
//! | Method and path | Body | Answer |
//! |---|---|---|
//! | `GET /v1/node` | | `NodeStatus` (templates, load, draining) |
//! | `POST /v1/node/drain` | `DrainRequest` | `NodeStatus` |
//! | `GET /v1/sandboxes?tenant=&ended_after=` | | `SandboxList` (all tenants, or `?tenant=`; with `ended_after`, also the sandboxes whose usage became final since) |
//! | `POST /v1/sandboxes` | `NodeCreate` | `201` `SandboxInfo` |
//! | `GET /v1/sandboxes/{id}` | | `SandboxInfo` |
//! | `DELETE /v1/sandboxes/{id}` | | `204` |
//! | `POST /v1/sandboxes/{id}/exec` | `ExecRequest` | `ExecResult` (runs it to its end) |
//! | `POST /v1/sandboxes/{id}/execs` | `ExecRequest` | `201` `ExecStatus` (once started) |
//! | `GET /v1/sandboxes/{id}/execs` | | `ExecList` (the latest exec) |
//! | `GET /v1/sandboxes/{id}/execs/{exec}?cursor=&wait=&max_bytes=` | | `ExecPoll` |
//! | `POST /v1/sandboxes/{id}/execs/{exec}/cancel` | | `ExecStatus` |
//! | `POST /v1/sandboxes/{id}/python/reset` | | `ResetResult` |
//! | `GET /v1/sandboxes/{id}/files?path=P` | | the bytes |
//! | `PUT /v1/sandboxes/{id}/files?path=P` | the bytes | `WriteResult` |
//! | `POST /v1/sandboxes/{id}/files/edit` | `EditRequest` | `EditResult` |

use std::sync::Arc;

use hellovm_control::http::{Handler, Request, Response};
use hellovm_control::ids::token_eq;
use hellovm_control::types::{self, DrainRequest, PollQuery, SandboxList};
use serde::de::DeserializeOwned;

use crate::node::{ApiError, Node};

/// The header naming the tenant a request is made for.
pub const TENANT_HEADER: &str = "x-hellovm-tenant";

pub struct NodeApi {
    pub node: Arc<Node>,
    pub token: String,
}

fn json_body<T: DeserializeOwned>(request: &Request) -> Result<T, ApiError> {
    serde_json::from_slice(&request.body)
        .map_err(|e| ApiError::new(400, "bad_request", format!("malformed JSON body: {e}")))
}

fn respond<T: serde::Serialize>(status: u16, result: Result<T, ApiError>) -> Response {
    match result {
        Ok(value) => Response::json(status, &value),
        Err(err) => err.response(),
    }
}

impl NodeApi {
    fn route(&self, request: &Request) -> Response {
        let segments = request.segments();
        let tenant = request.header(TENANT_HEADER);
        let node = &self.node;
        match (request.method.as_str(), segments.as_slice()) {
            ("GET", ["v1", "node"]) => Response::json(200, &node.status()),
            ("POST", ["v1", "node", "drain"]) => respond(
                200,
                json_body::<DrainRequest>(request).map(|r| node.set_draining(r.draining)),
            ),
            ("GET", ["v1", "sandboxes"]) => {
                let mut list = SandboxList {
                    sandboxes: node.list(request.query("tenant")),
                    ended: None,
                    ended_more: false,
                    boot: None,
                };
                if let Some(after) = request.query("ended_after") {
                    let Ok(after) = after.parse::<u64>() else {
                        return ApiError::new(400, "bad_request", "malformed ended_after")
                            .response();
                    };
                    let (ended, more, boot) = node.ended_after(after);
                    list.ended = Some(ended);
                    list.ended_more = more;
                    list.boot = Some(boot);
                }
                Response::json(200, &list)
            }
            ("POST", ["v1", "sandboxes"]) => {
                respond(201, json_body(request).and_then(|r| node.create(r)))
            }
            (method, ["v1", "sandboxes", id, rest @ ..]) => {
                let Some(tenant) = tenant else {
                    return ApiError::new(400, "bad_request", "no X-Hellovm-Tenant header")
                        .response();
                };
                match (method, rest) {
                    ("GET", []) => respond(200, node.info(id, Some(tenant))),
                    ("DELETE", []) => match node.delete(id, Some(tenant)) {
                        Ok(()) => Response::empty(204),
                        Err(err) => err.response(),
                    },
                    ("POST", ["exec"]) => respond(
                        200,
                        json_body(request).and_then(|r| node.exec(id, Some(tenant), &r)),
                    ),
                    ("POST", ["execs"]) => respond(
                        201,
                        json_body(request).and_then(|r| node.start(id, Some(tenant), &r)),
                    ),
                    ("GET", ["execs"]) => respond(200, node.execs(id, Some(tenant))),
                    ("GET", ["execs", exec]) => {
                        let query = PollQuery::parse(
                            request.query("cursor"),
                            request.query("wait"),
                            request.query("max_bytes"),
                        );
                        match query {
                            Ok(query) => respond(200, node.poll(id, Some(tenant), exec, query)),
                            Err(m) => ApiError::new(400, "bad_request", m).response(),
                        }
                    }
                    ("POST", ["execs", exec, "cancel"]) => {
                        respond(200, node.cancel(id, Some(tenant), exec))
                    }
                    ("POST", ["python", "reset"]) => respond(200, node.reset(id, Some(tenant))),
                    ("GET", ["files"]) | ("PUT", ["files"]) => {
                        let Some(path) = request.query("path") else {
                            return ApiError::new(400, "bad_request", "no ?path=").response();
                        };
                        if method == "GET" {
                            match node.read_file(id, Some(tenant), path) {
                                Ok(bytes) => Response::bytes(200, bytes),
                                Err(err) => err.response(),
                            }
                        } else {
                            respond(200, node.write_file(id, Some(tenant), path, &request.body))
                        }
                    }
                    ("POST", ["files", "edit"]) => respond(
                        200,
                        json_body(request).and_then(|r| node.edit_file(id, Some(tenant), &r)),
                    ),
                    _ => ApiError::new(404, "no_route", "no such endpoint").response(),
                }
            }
            _ => ApiError::new(404, "no_route", "no such endpoint").response(),
        }
    }
}

impl Handler for NodeApi {
    fn body_limit(&self, method: &str, path: &str) -> usize {
        if method == "PUT" && path.ends_with("/files") {
            types::MAX_FILE
        } else {
            types::MAX_JSON
        }
    }

    fn handle(&self, request: Request) -> Response {
        if !request.bearer().is_some_and(|t| token_eq(t, &self.token)) {
            return Response::error(401, "unauthorized", "a valid node token is required")
                .with_header("WWW-Authenticate", "Bearer".into());
        }
        self.route(&request)
    }
}
