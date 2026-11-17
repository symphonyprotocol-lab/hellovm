//! The node API: what `hellovm-api` calls. Every request carries the
//! node's bearer token; requests about one sandbox also name its tenant
//! (`X-Hellovm-Tenant`), and a sandbox of another tenant is reported as
//! missing, so a mistake in the API cannot reach across tenants here.
//!
//! | Method and path | Body | Answer |
//! |---|---|---|
//! | `GET /v1/node` | | `NodeStatus` |
//! | `GET /v1/sandboxes` | | `SandboxList` (all tenants, or `?tenant=`) |
//! | `POST /v1/sandboxes` | `NodeCreate` | `201` `SandboxInfo` |
//! | `GET /v1/sandboxes/{id}` | | `SandboxInfo` |
//! | `DELETE /v1/sandboxes/{id}` | | `204` |
//! | `POST /v1/sandboxes/{id}/exec` | `ExecRequest` | `ExecResult` |
//! | `GET /v1/sandboxes/{id}/files?path=P` | | the bytes |
//! | `PUT /v1/sandboxes/{id}/files?path=P` | the bytes | `WriteResult` |
//! | `POST /v1/sandboxes/{id}/files/edit` | `EditRequest` | `EditResult` |

use std::sync::Arc;

use hellovm_control::http::{Handler, Request, Response};
use hellovm_control::ids::token_eq;
use hellovm_control::types::{self, SandboxList};
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
            ("GET", ["v1", "sandboxes"]) => Response::json(
                200,
                &SandboxList {
                    sandboxes: node.list(request.query("tenant")),
                },
            ),
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
