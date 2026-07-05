# NeuralGuard — Design Decisions

Why this repo diverges from the original "NeuralGuard: On-Device ML Enforcement
Engine — Production Technical Specification." That document is a strong vision and
this project keeps its good bones; the decisions below are the corrections and the
scope cuts. ADR-style: each records the original position, the problem, and the call.

---

## The four correctness fixes

### D-1 — ML scores *completed flows*, not SYNs

- **Original:** every new flow is classified at `ALE_AUTH_CONNECT` by a 30-feature
  ONNX model, and blocked in <50 ms if malicious.
- **Problem:** the discriminative features — `bytes_total`, `packet_count`,
  `inter_packet_interval`, `payload_entropy`, `duration`, TLS/HTTP fields — do not
  exist at connect time; the spec itself labels them "per-flow / populated at
  FLOW_CLOSE." The model is then *trained* on CIC-IDS2018, whose records are
  completed bidirectional flow statistics. Training on full-flow features and
  inferring on connect-time features is train/serve skew; the advertised
  ≥97% AUC / <0.5% FP will not survive deployment.
- **Decision:** split into two decisions. The **connect** decision uses only
  features that exist at connect time (identity, port, protocol, time-of-day, geo/
  ASN, recent-frequency aggregates) via deterministic + habit logic. The **model**
  runs asynchronously on **completed** flows and governs *future* connections
  (block-next-time). Train and serve on the same shape → no skew, and the ML earns
  its keep on the problem it can actually solve.

### D-2 — Habit/verdict key is process+destination identity, not the 5-tuple

- **Original:** kernel fast-path verdict cache keyed on the full 5-tuple
  `(src_ip, dst_ip, src_port, dst_port, proto)`.
- **Problem:** the source port is ephemeral — a new value on every connection. A
  5-tuple key therefore misses for every *new* connection, even to a destination you
  reach constantly, so the "<1 µs fast path handles 99%" claim collapses into a
  slow-path ML round-trip per new flow.
- **Decision:** key habits and caches on
  `(process signer-thumbprint-or-image-hash, destination registrable-domain-or-ASN,
  remote_port, protocol)`. Stable across connections; a CDN's many IPs collapse to
  one habit; the fast path actually gets to be fast.

### D-3 — Measure per-connection behaviour, not throughput

- **Original:** success criteria include fast-path throughput ≥1 Gbps (PoC) / ≥10
  Gbps (prod).
- **Problem:** Gbps is a per-byte, data-path metric. Decisions happen per-connection
  at the ALE layer, off the byte path — so the target is either trivially met
  (we're not in the data path) or, once STREAM/DATAGRAM inspection is on, wildly
  optimistic for a user-mode round-trip. Category error.
- **Decision:** track new-connection verdict latency, first-contact prompt rate,
  false-block rate, habit cache-hit rate, and baseline coverage. Throughput becomes
  a real metric only for opted-in inspected flows if a Phase-5 driver ever exists.

### D-4 — No kernel driver in v1; enforce via block-notify-retry

- **Original:** a WFP **callout driver** holds the SYN in the kernel, asks user-mode
  AI, then releases it — and this is the *foundation*, required from Week 1, with EV
  cert + WHQL signing.
- **Problem:** (a) the "hold then release" handshake needs `FwpsPendClassify0` /
  `FwpsCompleteClassify0` / `FwpsReleaseClassifyHandle0`; the spec references only
  the completion call and never the pend/handle plumbing — the exact mechanism the
  design hinges on is under-specified. (b) A signed kernel callout driver is the
  single hardest, riskiest path in the space (BSODs, HVCI, EV cert, WHQL) and making
  it the foundation blocks everything else behind it.
- **Decision:** v1 is entirely **user-mode** (WFP management API). Enforcement is
  default-deny + **block-notify-retry** (the proven `simplewall`/TinyWall pattern):
  block the novel connection, prompt, and on *Allow* add a permit rule so the app's
  retry succeeds. A callout driver with a *correct* pend handshake is an **optional
  Phase 5**, taken only if it proves worth the cost.

---

## Scope cuts (dropped for a personal, single-machine tool)

Each is defensible for a funded product and re-openable later; none serves v1.

| Dropped | Reason |
|---------|--------|
| **Windows Security Center / Action Center registration** | Modern WSC only recognizes third-party security products through a **gated Microsoft partner program** (protected-process, Microsoft-signed registration). It is not the simple COM-call-plus-registry-write the spec describes, and it's irrelevant to a tool you run for yourself. |
| **EV certificate + WHQL attestation (as a v1 requirement)** | Only needed to load a *kernel driver* on other people's machines. User-mode v1 doesn't need it; it returns only with the optional Phase-5 driver. |
| **Enterprise MDM / GPO / ADMX, WFAS `.wfw` import-export** | Fleet-management surface. A personal tool has no fleet. |
| **Federated learning + differential privacy (ε=1.0), cloud model CDN, canary/PagerDuty infra** | The vision statement says *no telemetry leaves the device*. Local-only means most of this machinery solves a problem the architecture says it doesn't have. Training is off-device on **your own** archived data. |
| **ARM64 / QNN NPU inference path** | The models (GBM/RF) run in <2 ms on a CPU EP. NPU acceleration is a micro-optimization for a non-problem at this scale. |
| **Separate `NGUpdater.exe`, and a heavy UI framework from day one** | A standalone auto-updater is out of v1. Note the **system-tray GUI (`ngtray`) is *in* scope** — it ships in Phase 2 and is required (a `LocalSystem` service can't show UI; session-0 isolation forces a separate interactive-session process). What's dropped is committing to a heavy framework up front: the tray starts minimal (icon + toast prompts + panic) and grows a dashboard in Phase 3, implemented in whatever is least effort (C#/.NET recommended). |
| **10 Gbps throughput target** | See D-3. |

---

## Kept from the original spec

WFP sublayer + weight ordering above Defender · tiered fast/slow decision split ·
SPSC ring buffer (returns in Phase 5) · ONNX Runtime for on-device inference · SQLite
policy store · HMAC hashing of sensitive log fields · coexistence-by-layering rather
than ripping Defender out. The vision was sound; the corrections are about sequencing
and the point-of-decision, not direction.
