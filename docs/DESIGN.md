# NeuralGuard — Design

This is the architecture for the solo-buildable version. It reuses the good
structural ideas from the original enterprise spec and fixes the four core flaws
called out in [`DECISIONS.md`](DECISIONS.md).

Read this order: **Principles → Components → The decision pipeline → Identity →
Habit engine → Where ML actually lives → What we measure → Safety rails.**

---

## 1. Principles

1. **Telemetry before AI.** You cannot learn a baseline you never recorded. The
   first thing that works is passive logging with good process/destination
   attribution. Modelling comes after there is data to model.
2. **User mode first.** Everything through Phase 4 uses the WFP *management* API
   from a normal Windows service. A kernel callout driver is powerful but is also
   the thing that BSODs your box and needs EV/WHQL signing. Earn it later.
3. **The AI writes rules; deterministic code enforces them.** No model output is
   ever on the hot path of "should this packet pass." Models produce *rules* and
   *scores* that a boring, fast, auditable matcher applies.
4. **Two decisions, never one.** "Should I allow this new connection right now?"
   and "Is this pattern of behaviour trustworthy?" are different questions with
   different data available. Conflating them is the original spec's central bug.
5. **Fail toward a usable machine.** This runs on your daily driver. A missed
   block is recoverable; a firewall that won't let you reach the network (or the
   fix) is not.

## 2. Components (v1)

One background service, one tray app, one CLI, one database.

| Component | What it is | Responsibility |
|-----------|-----------|----------------|
| `ngd` | Windows service (user mode, runs as `LocalSystem`) | Owns the WFP session and sublayer; subscribes to WFP net events + relevant ETW; runs the decision pipeline; owns the habit engine and policy store; exposes a local control socket. |
| `ngtray` | System-tray app + GUI (runs in the interactive user session) | The face of NeuralGuard: tray icon showing mode, actionable toast prompts for novel connections, a status/rules dashboard window, and the panic button. Talks to `ngd` over the same named pipe as `ngctl`. See §2.1. |
| `ngctl` | Command-line control tool (scriptable / headless) | Same named pipe as `ngtray`, for scripting and headless boxes. `status`, `learn`, `enforce`, `allow`, `deny`, `rules`, `log`, `panic`. |
| `ngpolicy.db` | SQLite database | Rules, the habit tables, the flow-event archive, model metadata. |

> **Why the tray is a separate process, not part of the service.** `ngd` runs as
> `LocalSystem` in **session 0**, which has no desktop — a service physically
> cannot show a tray icon, a toast, or a window. Anything the user sees or clicks
> must come from a process in the interactive session. `ngtray` is that process.
> This isn't a style choice; it's Windows session isolation.

Telemetry sources `ngd` consumes:

- **WFP net events** (`FwpmNetEventSubscribe4`) — every allow/drop the engine sees.
  Enable the *Filtering Platform Connection* audit subcategory so you get allows,
  not just drops.
- **Process start/stop** (ETW `Microsoft-Windows-Kernel-Process`, or WMI) — to keep
  a live `PID → image path → signer/hash` table. PIDs are recycled; resolve early.
- **DNS client** (ETW `Microsoft-Windows-DNS-Client`, event 3008) — to map a
  destination IP back to the *domain the app actually asked for*, which is the
  identity we care about, not the raw IP.

### 2.1 The tray app — `ngtray`

The tray app is the primary way you interact with NeuralGuard, and it's a required
component (see the session-0 note above), not a nicety. It launches at logon and
connects to `ngd` over the ACL'd named pipe.

- **Tray icon = state at a glance.** Distinct icon/badge for **Learning**,
  **Enforcing**, **Paused**, and **Panic / failed-open**, so the machine's posture
  is always visible.
- **Right-click menu:** switch mode (Learn ↔ Enforce) · Pause for 15 min (temporary
  allow-all) · **Panic** (the kill switch, one click) · Open dashboard · Quit.
- **Actionable toast prompts.** When enforcement blocks a novel connection, a
  Windows toast appears — "`app.exe` wants to reach `api.example.com:443` (first time
  ever)" — with inline **Allow once / Always allow / Block** buttons. Your choice
  calls back to `ngd`, which writes the rule; the app's automatic retry then
  succeeds. This is what makes block-notify-retry usable. Rate-limited to avoid
  toast storms (collapse bursts from one process into a single prompt).
- **Dashboard window.** An always-available window: live connection feed, recent
  blocks each with their reason, the rule list (add / edit / remove), habit stats,
  the autonomy-level toggle, and the weekly digest. Can be a WebView2 control
  rendering `ngd`'s local status page, or native — either is fine.
- **Headless fallback.** On a box with no interactive session (or a blocked
  connection while you're not logged in), `ngd` still logs and applies the
  configured default; you reconcile from the dashboard later. `ngctl` covers
  scripting and remote/headless control.

**Implementation.** Because `ngtray` is its own process talking to `ngd` over a
pipe, its language is free. The pragmatic pick for a tray icon + actionable toasts
+ a small window is **C#/.NET (WinForms or WPF)** — far less boilerplate than C++
for exactly this — with **native Win32 `Shell_NotifyIcon` + WinRT toast
notifications** as the pure-C++ alternative if you'd rather keep the whole codebase
in one language.

## 3. The decision pipeline (per new connection)

A connection is authorized at the WFP **ALE** layers — `ALE_AUTH_CONNECT_V4/V6`
(outbound) and `ALE_AUTH_RECV_ACCEPT_V4/V6` (inbound). This fires **once per
connection**, not per packet — which is exactly why per-byte/Gbps thinking does
not apply here (see §7).

Each new connection runs through tiers, cheapest first. The first tier that
produces a verdict wins.

```
        new connection (ALE auth)
                 │
   ┌─────────────▼──────────────┐
   │ Tier 0 — Deterministic floor│  always-allow loopback/DHCP/DNS/NTP;
   │ (in-agent, microseconds)    │  explicit allow/deny rules; panic = allow-all
   └─────────────┬──────────────┘
                 │ no match
   ┌─────────────▼──────────────┐
   │ Tier 1 — Habit lookup       │  identity key (see §4) seen & permitted
   │ (SQLite / in-mem, sub-ms)   │  before, with enough weight → ALLOW
   └─────────────┬──────────────┘
                 │ novel / weak
   ┌─────────────▼──────────────┐
   │ Tier 2 — Mode-dependent     │  LEARN: allow + record
   │ default                     │  ENFORCE: block + prompt (block-notify-retry)
   └─────────────┬──────────────┘
                 │  (asynchronous, off the decision path)
   ┌─────────────▼──────────────┐
   │ Tier 3 — ML on completed    │  scores *finished* flows; proposes habit
   │ flows (Phase 4)             │  promotions / demotions; flags anomalies
   └────────────────────────────┘
```

### How enforcement works without a kernel driver

The original spec wanted to *hold the SYN* in the kernel, ask user-mode AI, then
release it — which requires a callout driver and the `FwpsPendClassify0` /
`FwpsCompleteClassify0` / `FwpsReleaseClassifyHandle0` handshake. We don't do that
in v1. Instead, from user mode:

- **Learning mode:** we add no blocking filters. We *observe* via net events and
  record. The machine behaves exactly as it did before, so it's safe to run for
  weeks.
- **Enforcement mode:** we install a **default-block** filter in our sublayer for
  un-learned traffic, plus specific **permit** filters (`FwpmFilterAdd0`) for
  everything in the learned baseline. When something new is blocked, `ngd` signals
  `ngtray`, which raises an actionable toast ("`app.exe` → `api.example.com:443`,
  first time ever — Allow once / Always / Block"). On *Allow*, `ngd` adds a permit
  rule; the app's automatic retry then succeeds. This is the proven `simplewall` /
  TinyWall pattern: slightly less slick than a true interception prompt, works fine
  in practice, and needs no driver.

Filters live in a dedicated sublayer with weight above Defender's built-in range
so our verdicts take precedence; permit/deny filter weights are ordered so a
specific decision short-circuits the default.

## 4. Identity — the thing habits are keyed on

This is fix #2. The verdict cache / habit key is **not** the 5-tuple. Source ports
are ephemeral, so a 5-tuple key never hits for a *new* connection to a place you
go every day. The stable identity is:

```
habit_key = ( process_identity , destination_identity , remote_port , protocol )
```

- **process_identity** — Authenticode **signer thumbprint** if the image is signed;
  otherwise **SHA-256 of the image file**. Path is kept for display but is not the
  key (apps move; malware picks familiar paths).
- **destination_identity** — the **resolved domain** (from DNS-ETW correlation
  within a few seconds of the connect), collapsed to its registrable domain; if no
  DNS is available, fall back to **ASN**, then to the raw IP as last resort. A CDN
  hands out dozens of IPs for one name — the *name* is the habit, not the IP.
- **remote_port + protocol** — kept raw.

Time-of-day is a *feature of* the habit, not part of the key (see §5).

## 5. Habit engine — boring math, on purpose

No neural net here. Frequency tables with exponential decay carry ~95% of the value
and stay fully explainable, which matters because every block needs a human-readable
"why."

For each `habit_key` we keep:

- `count` — decayed observation count. On each sighting: `count = count * 0.5^(Δt / half_life) + 1`, with `half_life ≈ 14 days`. Habits you stop exercising fade; habits you keep, persist.
- `first_seen`, `last_seen`.
- `hour_histogram[24]` and `dow_histogram[7]` — when this normally happens.
- `verdict_history` — allows/denies the user has made for this key.

**Novelty score** for a new connection = a function of (decayed count, recency,
how far outside the usual hour/day this is, and how many *new* destinations this
process has hit recently). Low novelty + established key → auto-allow. High novelty
→ Tier 2 default.

**Promotion / demotion.** A nightly compaction job:

- Promotes stable keys (seen ≥ N times across ≥ M distinct days at consistent
  times) into explicit auto-permit rules → they now resolve at Tier 0/1.
- Decays and evicts stale keys.
- Applies any block-next-time proposals from the ML tier (§6) *after* they clear a
  confidence gate — or after you approve them, depending on the configured
  autonomy level.

**Cold start** (the gap the original spec ignored): for the first `learn` window
everything is novel, so `ngd` starts in learning mode by definition and does not
enforce until you have a baseline and explicitly run `ngctl enforce`. The first
enforcement day will still surface a handful of legitimate-but-rare apps; that's
what the prompt flow is for.

## 6. Where ML actually lives (Phase 4)

This is fix #1. The model does **not** sit on the connect decision, because at the
SYN the discriminative features (bytes, packet timing, payload entropy, duration)
do not exist yet. Instead the model runs **asynchronously on completed flows**,
where those features are real and fully populated — so training data and serving
data are the same shape, and the train/serve skew is gone.

Two models, not one, because they cover different blind spots:

- **Supervised classifier** — trained off-device on a public IDS dataset (CICIDS2017
  or CTU-13) for the malicious classes, plus (once accumulated) your own labeled
  feedback (§6.2). Catches *known* attack patterns: C2-beaconing regularity, slow
  exfil byte ratios, port-scan fan-out.
- **Unsupervised anomaly scorer** (Isolation Forest) — trained *only* on your own
  archived flows. Needs no external data and no labels; it just answers "does this
  look like anything you've ever done before." Catches deviations the supervised
  model was never trained to recognize.

High supervised-malicious confidence on a currently-trusted habit → a proposed
*demotion*, applied via the promotion job (§5) behind a confidence gate. High
anomaly alone, with low supervised confidence → not a silent decision — it escalates
to a review item (dashboard flag / weekly digest), because a label-free score by
itself isn't grounds to touch a rule.

### 6.1 Feature vector — what's solid, what needs a spike

User mode has no packet payload, so every feature is metadata:

| Feature | Source | Confidence |
|---------|--------|------------|
| Destination fan-out, time-of-day/day-of-week deviation | Already computed — `habits` histograms (§5) | Solid |
| Process trust tier (signed / catalog-signed / unsigned) | Already computed — `identity` (§4) | Solid |
| Destination novelty (domain/ASN never seen, or rare) | Already computed — novelty score (§5) | Solid |
| Connection timing / inter-arrival regularity (beaconing) | Derivable from repeated `flow_events` rows for the same habit key | Solid |
| Flow duration | Time between the connect event and the connection disappearing from the TCP table (`GetExtendedTcpTable` polling) | Probably solid, needs verification |
| Bytes sent/received per flow | **Open question.** WFP net events don't carry byte counts; per-connection byte accounting in pure user mode likely means `GetPerTcpConnectionEStats` (Extended TCP Statistics), which isn't enabled by default and may need to be turned on per-connection or system-wide. Untested. | **Needs a spike before committing to it as a feature** |

If the byte-count spike doesn't pan out cleanly, the plan still works with
duration + timing + fan-out + trust + novelty — that's most of a NetFlow-style
feature set already, just without the volume dimension. Don't block the rest of
Phase 4 on it.

### 6.2 The feedback loop

Every prompt decision you make (Allow once / Always allow / Block) is a labeled
example — you telling the system, in real time, what the right call was for that
exact feature vector. Each one is written to a `feedback_labels` table (the flow's
feature snapshot + your decision + timestamp), separate from `flow_events`/`habits`
so it's clearly purpose-built for retraining, not conflated with the operational
tables.

**Be honest about its shape.** Phases 2–3 exist specifically to make prompts rare
once your baseline settles — which means this dataset accumulates *slowly*, by
design, and precisely because the rest of the system is working. It's realistically
a small, slow-growing set best used to **recalibrate thresholds and catch
personal-environment drift** over months, not a fast feedback loop that retrains a
meaningfully different classifier week to week. Size expectations accordingly.

Retraining is a **manual** offline step (a script you run yourself against the
public dataset plus whatever's accumulated in `feedback_labels`), not an automated
pipeline — there's no infrastructure here to auto-deploy a model that scores worse
than the one it replaced, and a solo personal tool doesn't need one yet.

### 6.3 Shadow mode — the same rollout pattern as enforcement itself

Phase 2 didn't ship a blocking filter until the panic switch existed first. Phase 4
follows the identical pattern: both models compute and log scores for every
completed flow as soon as they're wired up, visible in the dashboard/CLI, but
**take zero action** until a `meta('ml_mode')` flag is explicitly flipped from
`shadow` to `active` — which stays `shadow` by default even across an upgrade. This
is the window where you sanity-check the scorers against weeks of your own real
traffic before they're allowed to touch a single rule.

### 6.4 Data governance

Feature archival (§6.1) is **opt-in** (off by default) and **auto-purged** after a
configurable retention window. `feedback_labels` follows the same policy. The only
data that ever leaves the machine is nothing — training happens **on the dev host**,
using the **public** IDS dataset (which contains none of your traffic) plus
whatever archive/feedback tables you've chosen to accumulate locally; the trained
model is a static artifact you copy back, and inference happens entirely on-device.

Model: gradient-boosted trees (LightGBM → ONNX) as the supervised primary, Isolation
Forest → ONNX as the anomaly scorer, both run via ONNX Runtime CPU EP. Both are
small enough as tree ensembles that INT8 quantization isn't the relevant lever the
way it would be for a neural net — worth revisiting only if model size ever
actually becomes a problem.

## 7. What we measure (fix #3)

Gbps is a per-byte, data-path metric; we decide per-connection at the ALE layer and
are not in the byte path at all (until/unless a driver inspects streams). So we
track the things that actually describe this system:

| Metric | Why it matters | Rough target (personal machine) |
|--------|----------------|---------------------------------|
| New-connection verdict latency (Tier 0–1) | The user-visible cost of a decision | sub-millisecond in-agent |
| First-contact prompt rate after learning | Learning quality — should fall to near-zero once habits settle | a few prompts/day, trending down |
| False-block rate | The metric that gets firewalls uninstalled | ~zero after the first enforcement week |
| Habit cache-hit rate (correct identity key) | Validates fix #2 | high (most connections are to known places) |
| Baseline coverage before enforcing | Are we ready to flip modes? | e.g. ≥ 95% of a normal day auto-resolves |

If a stream-inspecting driver is ever added (Phase 5), *then* per-packet cost and
throughput become real metrics — but only for the opted-in inspected flows.

## 8. Safety rails

- **Develop in a VM.** All enforcement work happens in a Hyper-V VM with snapshots
  until it has earned trust on the physical box.
- **Panic switch.** One click in the `ngtray` menu — or `ngctl panic`, or a global
  hotkey — deletes every filter in NeuralGuard's sublayer, immediately failing open.
  This is the first feature to build after the sublayer exists, because the first
  enforcement bug *will* lock you out.
- **Always-exempt.** Loopback, DHCP (UDP 67/68 + DHCPv6), DNS (53), and NTP (123)
  are permitted unconditionally at Tier 0, forever. Without this, default-deny takes
  down name resolution and time sync and the whole box appears "offline."
- **Fail-open on agent death (v1).** A watchdog restarts `ngd`; if it can't, the
  sublayer's default action reverts to allow. A personal machine that can't reach
  the network is a worse outcome than one missed block. (A hardened, fail-closed
  posture is a deliberate later choice, not a v1 default.)
- **Everything is logged with a reason.** Every block/allow carries the tier and the
  rule/key that produced it, so "why did this get blocked" always has an answer.

## 9. Reused from the original spec (credit where due)

The enterprise document got a lot right, and this design keeps it: the WFP sublayer
approach and weight ordering; the tiered fast-path/slow-path split; the SPSC ring
buffer (relevant again *if* a driver arrives in Phase 5); ONNX Runtime for on-device
inference; SQLite as the policy store; privacy-preserving hashing of sensitive log
fields; and the coexistence idea of layering above Defender rather than ripping it
out. The changes are about *sequencing and correctness*, not throwing the vision away.
