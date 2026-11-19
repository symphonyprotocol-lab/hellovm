# hellovm-mcp

An MCP server (Model Context Protocol, stdio transport) that gives a
model one hellovm sandbox: shell commands, a persistent Python
interpreter, and file reads, writes and edits. Node.js 20 or later.

```sh
npm ci && npm run build          # in sdk/ts first, then here
HELLOVM_URL=http://127.0.0.1:7070 HELLOVM_TOKEN=... node dist/server.js
```

A client configuration (Claude Desktop, Claude Code and most clients use
this shape):

```json
{
  "mcpServers": {
    "hellovm": {
      "command": "node",
      "args": ["/path/to/hellovm/sdk/mcp/dist/server.js"],
      "env": { "HELLOVM_URL": "http://127.0.0.1:7070", "HELLOVM_TOKEN": "..." }
    }
  }
}
```

| Variable | Default | |
|---|---|---|
| `HELLOVM_URL` | (required) | the API's base URL |
| `HELLOVM_TOKEN` | (required) | the tenant's token; never written to tool results or logs |
| `HELLOVM_TEMPLATE` | `python` | the template sandboxes are made from |
| `HELLOVM_IDLE_TIMEOUT`, `HELLOVM_LIFETIME` | the API's | seconds, for the sandbox the server creates |
| `HELLOVM_SANDBOX` | | use this existing sandbox instead (never deleted by the server) |
| `HELLOVM_MCP_TIMEOUT`, `HELLOVM_MCP_MAX_TIMEOUT` | 60, 600 | a tool call's default and largest `timeout`, seconds |
| `HELLOVM_MCP_MAX_OUTPUT` | 16384 | bytes of each output stream, and of a file read, shown to the model |

Tools: `exec` (`command`, `timeout?`, `cwd?`), `python` (`code`,
`timeout?`, `restart?`), `read_file` (`path`), `write_file` (`path`,
`content`), `edit_file` (`path`, `old_text`, `new_text`,
`replace_all?`), `expose_port` (`port`, `public?`: the port's URL and
how to send the ingress token), `unexpose_port` (`port`), `reset_sandbox`. An API error is a tool error with the
API's code and message; a quota error (`budget_exceeded`,
`rate_limited`, `tenant_limit`, `memory_limit`) also says what the model
can do next. The repository's README explains the choices.
