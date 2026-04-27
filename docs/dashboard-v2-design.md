# Dashboard v2 design

This is the design doc for the second-generation `/dashboard` UI shipped by
the honeymcp binary. It records what changed, why, and what the surface looks
like before any code shifts. The goal is not to copy what T-Pot or Modern
Honey Network already do; the goal is to define what a single-binary MCP
honeypot dashboard should look like in 2026 when the bar is "tier-A
researcher opens it once and tells you what they think".

## Why a v2

The v1 dashboard (a single embedded `dashboard.html` polling `/stats` every
5s) hits its limits as soon as the question shifts from "how many requests"
to "what did this attacker actually do". Three concrete failures:

1. **No narrative.** A scanner three-pack (`initialize` /
   `notifications/initialized` / `tools/list`) and a six-step social
   engineering session look the same on a counter card. They are not the
   same finding.
2. **No MCP-specific affordances.** Every honeypot dashboard on the market
   gives you a method-frequency bar chart. None of them visualise the
   protocol-level shape of a session: what tools were enumerated, what was
   called, what diverged from the persona's published catalogue. That is
   the most interesting layer for MCP traffic.
3. **No honesty surface.** The is_operator filter exists at the schema
   layer (since 0.6.0) but the UI does not display it. A reader cannot tell
   from the v1 dashboard which corpus they are looking at.

## Design principles

- **Honest by default.** Every count on the page is the external corpus.
  Operator traffic is shown explicitly when toggled, never folded silently.
- **Narrative-first.** The unit of analysis is the session, not the request.
  A session has a story; the dashboard tells it.
- **MCP-native.** Visualisations exist that only make sense for an MCP
  honeypot. If the same chart could ship with a generic SSH honeypot, it is
  not pulling its weight.
- **Verify-yourself.** Every number is one click away from the raw event in
  SQLite. Build provenance is on every screen.
- **Zero build step for operators.** The dashboard ships in the binary. No
  `node_modules`, no separate frontend repo, no asset pipeline. Operators
  who clone the repo and run `cargo build --release` get the same UI as the
  hosted preview.

## Stack

| Layer       | Choice                                | Why                                  |
| ---         | ---                                   | ---                                  |
| Templates   | `minijinja` rendered server-side      | Compile-time safety, zero JS for layout, easy to embed in axum handlers |
| Interaction | `htmx` for partials, `Alpine.js` for local state | ~25 KB total. No React build step. SSR remains the source of truth |
| Live feed   | Server-Sent Events on `/dashboard/feed` | Already part of the transport layer for `/sse` and `/mcp` GET; reuse the streaming primitive |
| Charts      | `Observable Plot` ESM, ~80 KB         | Grammar-of-graphics, designed by the D3 author; covers timeline + sankey + heatmap without 270 KB of D3 |
| Style       | Hand-written CSS, custom design tokens | Tremor / shadcn / generic dashboard kits collapse into the same shape; honeymcp earns visual identity by not using one |
| Distribution| `include_str!` into the binary at compile time | Same model as v1 dashboard.html. No runtime asset path. |

## Components

The complete v2 surface ships eight components. This doc lists all eight so
the spec is reviewable in one pass; the first PR delivers the foundation
plus components 1 and 2, which carry the highest "no other dashboard has
this" weight.

### 1. Attack Story Timeline (PR 1)

Vertical timeline grouped by `session_id`. Each session is a card; each
event inside is a row. Detector hits are inline annotations. A click on
any row expands it to show:

- The full `params` blob (truncation marker preserved)
- The detector decision: which detectors fired, with what evidence
- The matching persona tool (or "unknown tool" badge if the call name was
  not in the persona catalogue)

The timeline is ordered newest-first. Sessions older than 24h collapse to
a one-line summary by default; the full 7-day window is available behind
a "load older" button so initial render stays under 200 ms.

**Why this matters:** an analyst reading week-six corpus will spend most
of their time in this view. Every other panel is supplementary.

### 2. MCP Sequence Diagram (PR 1)

Per-session SVG generated server-side. Lifecycle states across the x-axis:
`connect` -> `initialize` -> `tools/list` -> `tools/call` (zero or more) ->
`session-end`. Branches highlight where the attacker's path diverged from
the typical scanner shape.

A scanner three-pack renders as a tight three-step ladder. A real attacker
session renders as a longer ladder with inline tool-name badges and
detector strikes. The visual difference between the two is the point.

This is the component nobody else has shipped. It only makes sense for an
MCP honeypot because it encodes the protocol's session shape.

### 3. Persona-vs-Reality Sankey (PR 2)

Two-column sankey. Left: tools the active persona advertises. Right: tools
attackers actually invoked via `tools/call`. Width of each link encodes
the call count.

The visual claim of the project from the first-week blog post -- "tool
catalogue is advisory, not load-bearing" -- becomes a single-screen proof
the moment week-six corpus has any volume. Until that volume arrives this
panel renders an honest empty-state explaining the threshold.

### 4. Detector Co-occurrence Heatmap (PR 2)

7x7 heatmap of detector x detector. Cell colour encodes the conditional
probability that detector Y fires given that detector X fired in the same
event. `recon` x `tool_enumeration` should be hot; `secret_exfil` x
`unicode_anomaly` should be cool. Surface non-obvious correlations the
scalar bar charts cannot reveal.

### 5. Live Feed with honest badges (PR 3)

Streaming list of the latest events. Two visual states per row: green dot
external, grey dot operator. Default toggle is `external only`. The toggle
is a real query parameter (`?include_operator=true`) so the URL is
shareable; bookmarks survive operator changes.

This is the most explicit place where the methodology is shown to the
reader rather than buried in CHANGELOG.

### 6. Geo-IP Pulse Map (PR 3)

Small-multiples world map with one dot per resolved IP, animated forward
through the corpus window. No fake "1.4M attacks/sec" theatre. A counter
strip below the map shows the honest external-only number with a 24h
delta.

### 7. Build Provenance Footer (PR 4)

Discrete strip at the bottom of every page showing `version` `git_sha`
`build_time_utc` and a green tick reading `cosign verified` plus the
Rekor `logIndex`. The strip pulls live from `GET /version`. A click
expands a panel with the actual cosign verify command pre-filled with
the running image's digest.

### 8. Methodology Sidebar (PR 4)

Collapsible right-hand panel containing four sections:

- "What is honeymcp" -- two-paragraph explainer
- "What this dashboard counts" -- explicit statement of the operator
  filter, the event truncation cap, the JSONL retention window
- "What this dashboard does NOT show yet" -- planned components from
  this design doc
- A link to the week-one corrigendum blog post

The sidebar is dismissable but persists in `localStorage`, so a returning
operator gets the streamlined view, and a first-time visitor gets the
context.

## Routing

| Path                       | Method | Purpose                            |
| ---                        | ---    | ---                                |
| `/dashboard`               | GET    | Server-rendered shell + initial state |
| `/dashboard/feed`          | GET    | SSE stream of new events           |
| `/dashboard/session/{id}`  | GET    | HTML partial for one session card (htmx swap target) |
| `/dashboard/sequence/{id}` | GET    | SVG per-session sequence diagram   |
| `/dashboard/sankey.svg`    | GET    | Persona-vs-reality sankey image    |
| `/dashboard/heatmap.svg`   | GET    | Detector co-occurrence heatmap     |

Every endpoint is content-negotiated. `Accept: application/json` returns
machine-readable data so the same routes work for embedded reports and
external scrapers.

## Performance budget

- Initial paint: under 200 ms on a 4G connection.
- JS bundle: under 110 KB gzipped (htmx 13 KB + Alpine 12 KB + Plot 80 KB).
- CSS: under 8 KB. Hand-written, no purge pass.
- Time to first SSE event after page load: under 500 ms.

If a panel's render time exceeds 100 ms server-side, it ships behind an
htmx lazy-load placeholder. That keeps the cold dashboard load fast even
as the corpus grows past the SQLite friendly window.

## What this doc is not

- It is not a marketing claim. None of these components exists in code as
  of this commit. Treat the file as a contract for the next batch of
  PRs, not a status report.
- It is not a substitute for the corrigendum methodology. The dashboard
  shows numbers honestly; the question of which numbers are interesting
  in the first place still belongs to the blog.
