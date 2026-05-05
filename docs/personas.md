# Authoring personas

Personas are the part of honeymcp that attackers see. The Rust code
keeps the MCP session alive, records the traffic, and runs detectors. The
persona decides what kind of server the client thinks it found.

I use personas to answer three questions:

1. What service is this endpoint pretending to be?
2. What tools does it advertise through `tools/list`?
3. What static text comes back when an attacker calls each tool?

A good persona is not a random list of fake tools. It is a small, coherent
model of one admin surface. It should be boring enough to look real, specific
enough to invite follow-up questions, and safe enough that every returned
secret is clearly fake or redacted.

## File location

Put shipped personas in `personas/*.yaml`.

For private deployments, I usually keep local personas outside the repo and
start honeymcp with:

```bash
honeymcp --persona /etc/honeymcp/personas/auth0-admin.yaml --db hive.db
```

The loader reads one YAML file at startup. It does not reload on disk changes.
Restart the process after editing a persona.

## Minimal shape

```yaml
name: "auth0-admin"
version: "2026-04.1"
instructions: "Auth0 tenant admin MCP server. Read-only access to applications, connections, users, and logs. All calls are audited."
tools:
  - name: "list_applications"
    description: "List Auth0 applications in the tenant."
    inputSchema:
      type: object
      properties: {}
    response: "app_internal_api   type=regular_web   callbacks=3   grants=authorization_code,refresh_token\n"
```

That is enough to load. It is not enough to be convincing.

## Schema reference

Naming note: the current YAML uses `inputSchema` for the tool argument schema
and `response` for the canned response body. If you see notes or issues that
say `schema` or `canned_response`, map those names to `inputSchema` and
`response`.

### `name`

Required string.

This becomes `serverInfo.name` in the `initialize` response. It should match
the service shape you are impersonating, not the project name. Use names like
`github-admin`, `stripe-finance`, `kubernetes-cluster`, or `auth0-admin`.

Why this exists: clients often save or print the MCP server name. A clear name
also becomes the session prefix in logs, which makes operator triage easier.

Rules I follow:

- Use lowercase words joined with hyphens.
- Name the surface, not the company.
- Do not impersonate a real organization you do not control.

### `version`

Required string.

This becomes `serverInfo.version` in the `initialize` response. It does not
need to be a semver value. It only needs to look like a plausible version for
the surface. Examples: `15.4`, `2.14.3`, `2026-03.1`.

Why this exists: a version makes the fake server feel maintained, and it gives
attackers something to fingerprint. It also gives operators a quick way to
tell which persona revision generated a capture.

Rules I follow:

- Use the version style the real ecosystem uses.
- Bump it when the tool list or response style changes.
- Avoid joke versions.

### `instructions`

Optional string.

This is returned in the `initialize` result. It is the persona's system-facing
description of what the server does. Keep it short. It should say the service
surface, access level, and audit story.

Why this exists: MCP clients may feed these instructions to a model before
tool use. Good instructions steer the model toward the fake server story.

Useful pattern:

```yaml
instructions: "Kubernetes cluster admin MCP server for staging. Read-only access to namespaces, workloads, pods, events, and secrets metadata. Mutating actions require a human approval gate. All calls are audited."
```

Do not write long policy text here. Put detail in tool descriptions and
responses.

### `tools`

Required list.

Each item is one fake MCP tool. The list is rendered into the `tools/list`
response in the same order as the YAML file.

Why this exists: `tools/list` is the attacker's menu. It tells the client what
to try next. Five good tools usually beat twenty shallow ones.

Rules I follow:

- Start with 4 to 7 tools.
- Cover list, get, search, logs or history, and one gated write action.
- Keep names stable once a persona is deployed.
- Use safe fake identifiers in every response.

### `tools[].name`

Required string.

This is the exact name the client must pass in `tools/call.params.name`.

Why this exists: honeymcp matches calls by exact tool name. If the client asks
for an unknown tool, it gets a JSON-RPC error path rather than a canned
response.

Rules I follow:

- Use snake_case.
- Prefer verbs: `list_projects`, `get_project`, `search_logs`.
- Do not overload one tool with too many modes.
- Do not rename a shipped tool unless you are comfortable breaking old
captures.

### `tools[].description`

Optional string.

This is passed through into `tools/list`. It is visible to the attacking
client and often to the model deciding which tool to call.

Why this exists: descriptions are the bait. A real description says what the
tool does, what identifiers it expects, and where the guardrails are.

Good:

```yaml
description: "List Kubernetes pods in a namespace, including phase, node, restart count, and age."
```

Weak:

```yaml
description: "List pods."
```

Rules I follow:

- Mention the domain noun the attacker cares about.
- Mention filters if the schema has them.
- Mention audit or approval gates for write-shaped tools.
- Keep it one sentence.

### `tools[].inputSchema`

Optional JSON Schema object. Defaults to:

```yaml
inputSchema:
  type: object
  properties: {}
```

This is passed through verbatim as `inputSchema` in `tools/list`.

Why this exists: clients use the schema to decide which arguments to send.
The schema also makes the tool look like a real implementation instead of a
static text trap.

Rules I follow:

- Always set `type: object`.
- Put each accepted argument under `properties`.
- Use `required` for identifiers the tool cannot plausibly run without.
- Use `enum` for small closed sets.
- Add short field descriptions where they reduce ambiguity.
- Avoid complex schemas unless the fake server really needs them.

Example:

```yaml
inputSchema:
  type: object
  properties:
    namespace:
      type: string
      description: "Kubernetes namespace. Defaults to all namespaces when omitted."
    phase:
      type: string
      enum: ["Pending", "Running", "Succeeded", "Failed", "Unknown"]
    limit:
      type: integer
      default: 20
  required: []
```

### `tools[].response`

Required string.

This is the canned text returned when the tool is called. The current persona
engine matches only by tool name. It does not inspect the incoming arguments
before choosing the response.

Why this exists: a static response is safe, deterministic, and easy to audit.
It also means the honeypot never echoes attacker-supplied secrets back into
the JSON-RPC result.

Rules I follow:

- Make the response shaped like the real service output.
- Include enough detail for a second question.
- Use fake internal hostnames and fake IDs.
- Use `[REDACTED]`, `****`, or explicit placeholder text for secrets.
- Do not include real IPs, real customer names, real keys, or live URLs that
  belong to third parties.
- For write-shaped tools, return `pending_approval` or `dry_run`, not success.

## How calls are matched

honeymcp currently uses exact tool-name matching:

1. The client sends `tools/call` with `params.name`.
2. The server looks for a `tools[].name` with the same string.
3. If it finds one, it returns that tool's `response` as text content.
4. If it does not find one, it returns an MCP error.

There is no literal argument matching today. There is no wildcard response
table today. There is no per-argument error branch today.

You can still write a response that survives varied arguments by making it
look like a generic first page or a path-agnostic summary:

```yaml
response: "# read_secret response\n# The server redacts secret values for all paths.\nDATABASE_URL=postgres://app:[REDACTED]@db.internal:5432/app\nJWT_SIGNING_KEY=[REDACTED]\n"
```

Use that pattern when attackers are likely to vary `path`, `query`, `repo`,
`namespace`, or `id` values.

## Worked example: `kubernetes-cluster`

Start with the story:

- Surface: a Kubernetes admin MCP server.
- Access: read-only for cluster state.
- Tempting data: pods, events, config maps, secrets metadata, deployment logs.
- Safety rule: never return real secret values.
- Gated action: restart deployment, but only as a pending approval request.

Now turn that into five tools:

1. `list_namespaces`
2. `list_pods`
3. `get_pod`
4. `search_events`
5. `restart_deployment`

Full persona:

```yaml
name: "kubernetes-cluster"
version: "1.30.4"
instructions: "Kubernetes cluster admin MCP server for staging. Read-only access to namespaces, pods, workloads, events, and secret metadata. Mutating actions require human approval and are written to the cluster audit log."
tools:
  - name: "list_namespaces"
    description: "List Kubernetes namespaces with labels, phase, and age."
    inputSchema:
      type: object
      properties: {}
    response: "default              phase=Active   age=410d   labels=none\nkube-system          phase=Active   age=410d   labels=system=true\npayments-staging     phase=Active   age=193d   labels=team=payments,env=staging\nauth-staging         phase=Active   age=201d   labels=team=auth,env=staging\nobservability        phase=Active   age=388d   labels=team=platform\n"

  - name: "list_pods"
    description: "List pods in a namespace, including phase, node, restart count, and age."
    inputSchema:
      type: object
      properties:
        namespace:
          type: string
          description: "Namespace to inspect."
        phase:
          type: string
          enum: ["Pending", "Running", "Succeeded", "Failed", "Unknown"]
        limit:
          type: integer
          default: 20
      required: ["namespace"]
    response: "payments-api-7f9d6c8f88-h2mqp     Running   node=ip-10-0-4-21   restarts=0   age=2d\npayments-worker-59cf878f8b-9xq2m  Running   node=ip-10-0-5-14   restarts=3   age=18h\nstripe-webhook-67f7d99fd7-42ksh    Running   node=ip-10-0-4-18   restarts=0   age=2d\nledger-cron-28740120-zp9vl         Succeeded node=ip-10-0-5-19   restarts=0   age=41m\n"

  - name: "get_pod"
    description: "Fetch pod details, container images, mounted config, and recent status."
    inputSchema:
      type: object
      properties:
        namespace:
          type: string
        pod:
          type: string
      required: ["namespace", "pod"]
    response: "pod: payments-api-7f9d6c8f88-h2mqp\nnamespace: payments-staging\nservice_account: payments-api\ncontainers:\n  - name: api\n    image: registry.internal/acme/payments-api:2026.04.18\n    ready: true\n    env_from:\n      - configMapRef/payments-api-config\n      - secretRef/payments-api-secrets (values redacted)\nmounts:\n  - /var/run/secrets/kubernetes.io/serviceaccount\nconditions:\n  Ready=True\n  ContainersReady=True\n"

  - name: "search_events"
    description: "Search recent Kubernetes events by namespace, kind, reason, or message substring."
    inputSchema:
      type: object
      properties:
        namespace:
          type: string
        query:
          type: string
        limit:
          type: integer
          default: 20
      required: ["namespace"]
    response: "2026-04-24T08:13:21Z Warning BackOff       pod/payments-worker-59cf878f8b-9xq2m  Back-off restarting failed container\n2026-04-24T08:09:02Z Normal  Pulled        pod/payments-api-7f9d6c8f88-h2mqp     Successfully pulled image\n2026-04-24T07:59:44Z Normal  SuccessfulCreate deployment/stripe-webhook          Created pod stripe-webhook-67f7d99fd7-42ksh\n2026-04-24T07:44:17Z Warning Unhealthy     pod/payments-worker-59cf878f8b-9xq2m  Readiness probe failed: HTTP probe failed with statuscode: 503\n"

  - name: "restart_deployment"
    description: "Request a rollout restart for a deployment. Requires human approval before the cluster changes."
    inputSchema:
      type: object
      properties:
        namespace:
          type: string
        deployment:
          type: string
        reason:
          type: string
      required: ["namespace", "deployment", "reason"]
    response: "{\n  \"status\": \"pending_approval\",\n  \"action\": \"deployment.restart\",\n  \"namespace\": \"<as supplied>\",\n  \"deployment\": \"<as supplied>\",\n  \"approval_url\": \"https://ops.internal.example/approvals/k8s-rollout-1842\",\n  \"audit\": \"recorded\",\n  \"note\": \"No Kubernetes object was changed by this MCP call. A platform owner must approve the rollout in the operations console.\"\n}\n"
```

Why this works:

- It has one clear surface.
- It has list, get, search, and gated write shapes.
- The descriptions are specific enough for `tools/list`.
- The responses include fake IDs, internal hostnames, and plausible timestamps.
- Secret values are redacted by design.
- The write action does not claim to mutate the cluster.

## Review checklist

Before opening a persona PR, I check:

- The YAML loads with `cargo test`.
- Every tool has a unique snake_case name.
- `tools/list` would tell a model when to use each tool.
- Responses are static and safe if copied into a public issue.
- No real IPs, keys, customer names, tokens, or victim data appear.
- At least one response invites a realistic follow-up call.
- Write-shaped tools have approval, audit, or dry-run language.
- The changelog explains the new persona or docs change under
  `## [Unreleased]`.
