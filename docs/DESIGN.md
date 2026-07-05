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

One service, one CLI, one database. No separate updater/UI processes yet.

| Component | What it is | Responsibility |
|-----------|-----------|----------------|
| `ngd` | Windows service (user mode, runs as `LocalSystem`) | Owns the WFP session and sublayer; subscribes to WFP net events + relevant ETW; runs the decision pipeline; owns the habit engine and policy store; exposes a local control socket. |
| `ngctl` | Command-line control tool (later: a WinUI/tray front-end) | Talks to `ngd` over a named pipe with a tight ACL. `status`, `learn`, `enforce`, `allow`, `deny`, `rules`, `log`, `panic`. |
| `ngpolicy.db` | SQLite database | Rules, the habit tables, the flow-event archive, model metadata. |

Telemetry sources `ngd` consumes:

- **WFP net events** (`FwpmNetEventSubscribe4`) — every allow/drop the engine sees.
  Enable the *Filtering Platform Connection* audit subcategory so you get allows,
  not just drops.
- **Process start/stop** (ETW `Microsoft-Windows-Kernel-Process`, or WMI) — to keep
  a live `PID → image path → signer/hash` table. PIDs are recycled; resolve early.
- **DNS client** (ETW `Microsoft-Windows-DNS-Client`, event 3008) — to map a
  destination IP back to the *domain the app actually asked for*, which is the
  identity we care about, not the raw IP.

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
  everything in the learned baseline. When something new is blocked, `ngd` raises a
  prompt ("`app.exe` → `api.example.com:443`, first time ever — allow?"). On
  *Allow*, we add a permit rule; the app's automatic retry then succeeds. This is
  the proven `simplewall` / TinyWall pattern: slightly less slick than a true
  interception prompt, works fine in practice, and needs no driver.

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

Its outputs feed back into the habit store, not the packet path:

- **Block-next-time proposals.** A finished flow that scores malicious (C2-beaconing
  regularity, slow exfil byte ratios, port-scan fan-out) produces a proposed
  *demotion* of that habit key. Applied via the promotion job behind a confidence
  gate (§5).
- **Anomaly flags.** An unsupervised scorer (e.g. Isolation Forest) gives a second,
  label-free opinion; high anomaly + low supervised confidence = escalate to a
  review item rather than a silent decision.
- **Weekly digest.** "Here's what changed in your network life this week; here are
  3 things that look off." A natural, *offline, advisory-only* place for an LLM to
  summarize — it explains, it never enforces.

Model: gradient-boosted trees (LightGBM → ONNX) as the primary, exported and run via
ONNX Runtime CPU EP. Trained off-device on your own archived completed-flow features
plus a public IDS dataset for the malicious classes. Small, fast, explainable via
feature importances.

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
- **Panic switch.** `ngctl panic` (and a global hotkey once there's a UI) deletes
  every filter in NeuralGuard's sublayer, immediately failing open. This is the
  first feature to build after the sublayer exists, because the first enforcement
  bug *will* lock you out.
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
