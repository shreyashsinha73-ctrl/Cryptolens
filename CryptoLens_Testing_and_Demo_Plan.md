# CryptoLens — Testing, Validation & Demo Pipeline Plan

---

# PART 1: Testing Philosophy — Four Levels

Before the component breakdown, fix the four levels you're testing at, because "stress test" means something different at each:

1. **Unit-level correctness** — does this one function/module produce the right output for a known input? (e.g., "given this exact IKE proposal payload, does the parser extract AES-256-GCM correctly?")
2. **Component-level integration** — does this stage correctly hand off to the next stage in the format the next stage expects?
3. **Stress/robustness** — does the component survive malformed, missing, excessive, or adversarial input without silently producing a wrong-but-plausible-looking answer? (This is the dangerous failure mode in a security tool — wrong-but-confident is worse than a crash.)
4. **End-to-end (E2E) regression** — given a known lab configuration (ground truth you built yourself), does the *whole pipeline*, run start to finish, arrive at the correct final score and report?

Every component below gets tested at levels 1–3. Level 4 is Part 2.

---

# PART 2: Component-by-Component Test & Stress Plan

## 2.1 Testbed & Infra (Stage 1)

**What "correct" means here:** every row in `config_matrix.yaml` actually produces a real, working IPsec tunnel with exactly the parameters you asked for — not "a tunnel," but *the specific tunnel you specified*.

| Test | How to run it | Pass criteria |
|---|---|---|
| Config fidelity | For each generated config, run `swanctl --list-sas` / `ipsec statusall` after tunnel-up and diff the *actual* negotiated cipher/DH/mode against what `config_matrix.yaml` requested | 100% match, every row, every rebuild |
| Full matrix sweep | Script that tears down and brings up **every** config in the matrix in sequence, unattended | Every config comes up within a fixed timeout (e.g., 10s); zero manual intervention |
| Traffic generator fidelity | Capture each generator's output in isolation (no tunnel) and inspect packet-size/timing distributions in Wireshark | ICMP: fixed size, fixed interval. VoIP sim: small, tight timing variance. HTTPS: bursty, variable size. Distributions must be visibly distinct from each other — if two generators look statistically identical, your AI stage has nothing to learn from |
| Replay test correctness | Run `inject_duplicate_esp.py` against a tunnel with anti-replay **enabled**, then again against one with it **disabled** (if strongSwan allows disabling it) | Enabled: duplicate is dropped (confirm via strongSwan logs/counters). Disabled: duplicate is accepted. If you can't get a true negative case, the test isn't proving anything — flag this to your team |
| **Stress: rapid rebuild loop** | Bring the same tunnel up/down 50+ times back-to-back | No leaked namespaces, no zombie processes, no port/SPI collisions, consistent capture output each time |
| **Stress: concurrent tunnels** | Bring up 3–4 different configs simultaneously in separate namespace pairs | No cross-talk between tunnels' traffic in captures; each capture only contains its own tunnel's packets |
| **Stress: capture volume** | Run a traffic generator for an extended period (minutes, not seconds) through one tunnel | tshark capture file doesn't corrupt, doesn't drop packets silently, disk usage is bounded/rotated if needed |
| **Stress: clean-machine deploy** | Run `docker-compose up` on a machine that has never seen this project before (or `docker system prune -a` first) | Comes up with zero manual fixes — this is your literal live-demo failure mode, so this test *is* your demo insurance |

## 2.2 Capture & Demux (Stage 2)

**What "correct" means:** every packet ends up in the right bucket (control vs data), and the demux doesn't silently misclassify or drop packets.

| Test | How to run it | Pass criteria |
|---|---|---|
| Port/protocol demux accuracy | Feed a known-composition pcap (X control packets, Y data packets, counted by hand) through the demux | Output control-track count == X, data-track count == Y, zero packets unaccounted for |
| NAT-T handling | Generate a capture where IKE floats to port 4500 (NAT-Traversal) | Demux still correctly buckets these as control-track, not misfiled as data |
| **Stress: truncated capture** | Feed a pcap that starts mid-session (deliberately delete the first N packets, simulating "capture started late") | Demux doesn't crash; correctly flags "no `IKE_SA_INIT` observed" so downstream knows to fall back to the AI path — this is the exact trigger condition your own architecture document describes, so this test *must* pass before you can honestly claim that fallback logic works |
| **Stress: malformed/corrupted packets** | Feed a pcap with a few bytes randomly flipped (fuzz a copy of a real capture) | Demux/parser fails *loudly* (logs an error, skips the packet) — never silently produces a plausible-looking wrong field |
| **Stress: very large pcap** | Feed a multi-GB or multi-hour capture (synthetic if needed) | Processes without OOM-killing the container; reasonable linear time, not exponential blowup |

## 2.3 Control-Plane Engine (Parser + Rule Engine)

**What "correct" means:** given a real handshake, the extracted AST matches the config you know you built (ground truth from Section 2.1), field for field.

| Test | How to run it | Pass criteria |
|---|---|---|
| Ground-truth cross-check | For every config in your matrix, run the parser against its capture and diff extracted {IKE version, cipher, DH group, PRF, auth algo, mode} against the matrix row | Exact match, every field, every config — this is your single most important correctness test, since your entire pitch rests on "deterministic parsing is 100% accurate when the handshake is visible" |
| IKEv1 vs IKEv2 handling | Include at least one config of each version (if your matrix has both) | Parser correctly identifies version and doesn't apply the wrong payload-parsing logic to the wrong version |
| **Stress: Aggressive Mode** | Force one IKEv1 tunnel into Aggressive Mode (fewer round trips, different payload order) | Parser still extracts correct fields — you list this exact case as a roadmap item, so at minimum the MVP should *detect* Aggressive Mode and flag it as "reduced negotiation visibility" rather than mis-parsing it |
| **Stress: SA lifetime extraction** | If you took the earlier recommendation to add key-lifetime scoring, verify extraction against a config where you deliberately set a known lifetime value | Extracted lifetime matches configured lifetime exactly |
| **Stress: retransmissions** | Force a lossy link (e.g., `tc netem` packet loss on the veth) so IKE retransmits some packets | Parser doesn't double-count retransmitted payloads or get confused by duplicate SA proposals |

## 2.4 Data-Plane / Inference Engine (AI Component)

This is where "stress testing" means something closer to **statistical validation**, not just crash-testing.

| Test | How to run it | Pass criteria |
|---|---|---|
| Held-out accuracy | Split your labeled dataset: train/tune on one portion, evaluate on a portion the model never saw | Report per-class precision/recall/F1 for both {Tunnel, Transport} and {traffic types}. Don't just report one "accuracy %" number — a model that's 95% accurate only because 95% of your data is one class is not actually working |
| Confusion matrix | Run the full held-out set through and tabulate predicted-vs-actual | Look specifically at which pairs get confused (e.g., is VoIP being mistaken for ICMP because both are small/regular?) — this becomes a slide in your technical report, not just a QA step |
| Confidence calibration | Bucket predictions by the model's stated confidence (e.g., 90–100%, 70–90%, etc.) and check actual accuracy within each bucket | High-confidence predictions should actually be more accurate than low-confidence ones. If a "95% confident" bucket is only 60% correct, your confidence score is misleading and needs recalibrating (or replacing with something you actually derive from validation accuracy, per the earlier recommendation) |
| **Stress: N-packet sensitivity** | Re-run classification using only the first 10, 20, 30, 50 packets of a session | Establishes the actual minimum signal needed — you claim N=30 is enough; prove it rather than assert it |
| **Stress: traffic-shaping/padding countermeasures** | Deliberately pad packets to a fixed size (many VPNs/apps do this) or inject artificial timing jitter, then re-classify | Document the accuracy drop honestly — your own plan already states this as a known limitation (Section 4), so this test is what turns that from a disclaimer into a measured, defensible number |
| **Stress: API failure modes** (if keeping the cloud path) | Simulate timeout, rate-limit response (HTTP 429), and malformed JSON response from the API | Pipeline falls back gracefully (cached result / explicit "inference unavailable" flag on the dashboard) — never hangs, never crashes the whole assessment |
| **Stress: concurrent batch load** | Fire multiple sessions' worth of classification requests at once | No cross-contamination of results between sessions; latency stays within your demo's acceptable window |

## 2.5 Scoring Engine

**What "correct" means:** the formula in Section 5 of your plan produces the number it's supposed to, every time, for every input — this is pure arithmetic, so it should be tested like arithmetic.

| Test | How to run it | Pass criteria |
|---|---|---|
| Hand-calculated unit tests | Write out, by hand, the expected `S_sec` for at least 5–6 representative configs (best case, worst case, a couple of middling cases) using the formula in Section 5, then feed the same inputs through the actual scoring code | Code output matches hand calculation to the decimal, for every case |
| Boundary/edge cases | Feed inputs like "unknown cipher," "cipher present but DH group missing," "PFS field absent entirely" | Engine either has a defined default/penalty for missing data, or explicitly flags "incomplete data — score not computed," but never crashes or silently defaults to a value that inflates the score |
| Monotonicity check | Take one known-good config and degrade exactly one parameter at a time (drop DH group, disable PFS, etc.) | Score must decrease each time you weaken one thing — if weakening a parameter ever *increases* the score, there's a sign error in the formula, and this is the cheapest possible way to catch it before a judge does |
| **Stress: garbage/adversarial input** | Feed intentionally nonsensical AST (e.g., negative lifetime values, empty payload lists) | Fails safe — reports "cannot assess," never fails open with a falsely high score |

## 2.6 Reporting (PDF Generator)

| Test | How to run it | Pass criteria |
|---|---|---|
| Field population | Generate reports for your best-case and worst-case configs | Every field in the template is populated with real data — no leftover placeholder text, no blank sections |
| Extreme values | Force a score of 0 and a score of 100 (even artificially) through the report generator | Layout doesn't break (e.g., threat matrix with zero entries, or with every entry CRITICAL, should both render cleanly) |
| **Stress: concurrent report generation** | Trigger 3+ report generations at once | No file-write collisions, no cross-contaminated reports |

## 2.7 Dashboard

| Test | How to run it | Pass criteria |
|---|---|---|
| Live update correctness | Run a full assessment and confirm the score dial, threat matrix, and confidence bar all reflect the actual backend output, not stale/cached values | Values match backend response exactly |
| **Stress: rapid re-runs** | Trigger several assessments back-to-back in the UI without refreshing the page | No stale data lingering from the previous run; no UI freeze |
| **Stress: worst-case display** | Force a CRITICAL-everywhere result through the UI | Threat matrix, colors, and score dial all render legibly rather than overflowing or clipping |

## 2.8 Deployment

| Test | How to run it | Pass criteria |
|---|---|---|
| Fresh-machine bring-up | `docker-compose up` on a completely clean machine/VM | Comes up with zero manual steps — this is the test that directly de-risks your live demo |
| **Stress: resource-constrained bring-up** | Run under artificially limited CPU/RAM (e.g., `docker run --memory=2g --cpus=1`) | Either works within constraints, or fails with a clear error rather than hanging silently — good to know your real floor before you're on a venue's wifi/laptop |
| **Stress: network partition** | Kill network access mid-assessment (simulating venue wifi dropping) | Whatever your fallback path is (cached inference, pre-recorded capture) actually engages — test the thing you wrote in your own risk table (Section 11), don't just write it down |

---

# PART 3: The End-to-End Pipeline — How It Should Actually Run

Once every component passes its own tests, the thing that matters is that data flows correctly *between* them without manual intervention. This is the sequence to validate as one continuous run, with no human touching intermediate files:

```
1. Operator selects a config row (or "auto-run full matrix")
        │
2. Testbed brings up strongSwan tunnel with that exact config (Stage 1)
        │
3. Traffic generator(s) run across the tunnel for a fixed duration
        │
4. tshark captures the full session → single .pcap, tagged with a run ID
        │
5. Demux splits the .pcap into control-track and data-track streams (Stage 2)
        │
6. Control-plane engine parses control-track → AST (JSON)
        │           │
        │           ├─ If IKE_SA_INIT present & complete → deterministic path used
        │           └─ If missing/truncated/mid-session → flag set for AI fallback
        │
7. Data-plane engine:
        │  - extracts S_L (packet lengths) and S_IAT (inter-arrival times) from data-track
        │  - if deterministic mode-detection succeeded in step 6, mode is already known;
        │    AI is only invoked for inner-traffic-type prediction
        │  - if step 6 flagged a fallback, AI is invoked for BOTH mode and traffic type
        │
8. Scoring engine combines: AST fields (from 6) + inference outputs (from 7)
        │  → computes S_sec, S_risk, per-sub-score breakdown, threat matrix
        │
9. Reporting engine renders PDF (executive summary + technical detail)
        │
10. Dashboard receives the same structured result object and renders it live
        │
11. (Separately, not blocking the above) Replay-test module runs its own
     active injection test and reports a pass/fail flag alongside the rest
```

**The single most important end-to-end test:** run this exact sequence, unattended, for **every row in your config matrix**, and log the final score for each. Then sanity-check the *list* of scores, not just individual runs:

- Scores should roughly rank in the order you'd expect from security knowledge alone (AES-256-GCM/DH19/PFS-on should clearly outscore 3DES/DH2/PFS-off) — if your ranking doesn't match basic crypto intuition, something upstream is wrong, even if each component passed its own tests in isolation.
- Run the **same config twice** (rebuild the tunnel from scratch, re-capture, re-run) and confirm you get the same score both times — nondeterminism here (especially from the AI path) is something you want to know about *before* a judge re-runs your demo and gets a different number the second time.
- Run the **fallback path deliberately** (start a capture mid-session, per your own architecture note) and confirm steps 6→7 actually hand off correctly — this is the one branch in your whole pipeline that's easy to build and never actually exercise until demo day.

---

# PART 4: What to Show in the Demo Video

Your MVP plan's Section 7 already sketches a good live-demo script — here it is tightened into an actual video structure, with the reasoning for each beat and the **exact frontend state** that should be on screen, so every shot earns its place and nothing shown is a mockup.

| # | Segment | What's on screen | Exact frontend/dashboard state to show | Why this beat, specifically |
|---|---|---|---|---|
| 1 | **Hook (10–15s)** | One sentence + a visual of a Wireshark trace that "looks fine" next to the same trace's actual CryptoLens score (low) | A raw Wireshark window side-by-side with the CryptoLens score dial already showing a low number for that same capture — no dashboard interaction yet, just the contrast | Establishes the entire premise in one image: *looking secure ≠ being secure* |
| 2 | **One-command bring-up** | Terminal: `docker-compose up`, tunnel comes up | Terminal only — dashboard should be shown loading/empty state right after, so viewers see it come up from nothing rather than starting pre-populated | Directly demonstrates the deployment claim from your own deliverables list — don't skip past this, it's proof the fresh-machine test in 2.8 actually passed |
| 3 | **Good tunnel, live** | Bring up AES-256-GCM/DH19/PFS-on config; run HTTPS + VoIP traffic | Dashboard's **connection/tunnel-status indicator** flips from "no active tunnel" to "tunnel up," showing the negotiated parameters (cipher, DH group, mode) as soon as they're parsed — this proves the control-plane parsing, not just the AI path | Establishes the "known good" baseline the rest of the video will contrast against |
| 4 | **Analysis + score (good case)** | Dashboard populates live: score ≈ 90+, threat matrix mostly green, confidence bar visible | Full dashboard view: **score dial** animating up to ~90+, **per-sub-score breakdown** (C/K/M/E/PQC) each shown individually, **threat matrix** rendering mostly green/low-severity rows, **AI confidence bar** sitting high since this session likely used the deterministic path | Shows the full pipeline working end-to-end on a case with nothing to hide — this is also where you prove the sub-score breakdown exists, not just one number |
| 5 | **Reconfigure to bad tunnel, live** | Same commands, different config file: 3DES + DH Group 2 + PFS off + Aggressive Mode | Dashboard's tunnel-status indicator updates to the new negotiated parameters live — visually confirm on screen that cipher/DH group shown really did change, before the score updates | Same traffic, same pipeline — isolates the variable being demonstrated (config quality) from everything else |
| 6 | **Score collapse** | Score drops sharply on screen; threat matrix flips to CRITICAL on the specific rows (cipher, key exchange) | **Score dial** animating/dropping from ~90 to the new low value, **threat matrix rows for Cipher and Key Exchange specifically** flipping to red/CRITICAL while other rows stay unaffected — the row-level granularity is the point, so don't just show the top-line number | This is your core "we score, not just parse" differentiator — linger on this shot, it's your strongest visual |
| 7 | **PDF report auto-generation** | Show the generated report opening, scroll to the remediation section | Click the dashboard's **"Generate Report" / "Export" button** on screen (don't cut to a pre-made PDF — show the button being pressed), then the PDF opening with the **risk score, threat table, and top-3 remediation list** visible | Proves deliverable #4 (auto-generated report) isn't just a mockup, and shows the dashboard-to-report handoff is real |
| 8 | **Encrypted-only inference** | Load a capture with the handshake withheld; show CryptoLens correctly flag "no control-plane data — falling back to inference," then correctly output Tunnel Mode + VoIP from ESP metadata alone, with its confidence score displayed | Dashboard should show an explicit **"Control-plane data unavailable — using AI inference" banner/badge** (this state needs to actually exist in the UI, not be implied) before the mode/traffic-type fields populate; **confidence bar shown at the actual validated level** for that traffic class, not a generic high number | This is your single most technically impressive beat — it's the one thing "a Wireshark wrapper" fundamentally cannot do. Make sure the confidence number shown here is one you've actually validated in Part 2.4/5.4, not an unverified self-report |
| 9 | **Replay test** | Trigger `inject_duplicate_esp.py` live, show the "Replay protection: confirmed" flag populate in real time | A distinct **"Replay Protection" indicator/card** on the dashboard (separate from the threat matrix, since it's a live test result, not an inferred score) flipping from "untested"/greyed-out to "Confirmed" with a green check, in real time as the script runs on screen alongside it | Demonstrates an *active, provable* test rather than another inference — a good contrast beat right after the inference-heavy segment 8 |
| 10 | **Close (10–15s)** | One slide: differentiators (Section 8 of your plan) + standards logos (NIST/CNSA) if you have them | Static slide, not the dashboard — deliberately step outside the live UI here so the closing message reads as a takeaway, not another feature | Leaves judges with the "why this, not just another Wireshark GUI" takeaway explicitly, rather than assuming they inferred it |

**Frontend elements that must exist and be shown at least once, or the video is claiming features it can't back up:**
- Tunnel-status indicator showing live-parsed negotiated parameters (segments 3, 5)
- Score dial with visible animation/transition between values (segments 4, 6) — a static number swap is less convincing than an animated drop
- Per-sub-score breakdown (C/K/M/E/PQC), not just the top-line score (segment 4)
- Threat matrix with row-level severity, showing that specific rows change independently (segment 6)
- Report export button as an actual click, not a jump-cut (segment 7)
- A visible, explicit fallback-mode banner when control-plane data is missing (segment 8) — if this state isn't a real UI element yet, build it before recording, since it's the visual proof of your architecture's headline claim
- A separate, distinctly-styled replay-protection indicator, not folded into the threat matrix (segment 9)
- AI confidence bar shown at least twice (segments 4 and 8) so viewers can see it differ between the deterministic-heavy case and the inference-heavy case

---

# PART 5: The Inference Model — Architecture & Accuracy Targets

*(This assumes the team goes with a locally trained classifier for mode/traffic-type inference, per the earlier recommendation, implemented as a 1D CNN specifically. If a different architecture is chosen, the accuracy targets below still apply — only the "how it works" section changes.)*

## 5.1 What the model is

A 1D CNN treats a session's first N (~30) packets as a short two-channel time series: channel 1 = packet lengths, channel 2 = inter-arrival times, both normalized. Small convolutional filters slide across this sequence and learn to detect local motifs — a consistent size step (the structural offset tunnel mode adds by wrapping an extra IP header), or a repeating spacing pattern (VoIP's regular timing). A shared trunk of Conv1D + ReLU + pooling layers feeds two separate output heads:
- **Mode head**: binary (Tunnel vs Transport)
- **Traffic-type head**: multi-class (HTTPS / VoIP / ICMP / etc.)

This is a well-suited architecture for this exact kind of structural fingerprinting, but it needs a reasonably sized, augmented training set to generalize rather than memorize — with a small hackathon-scale dataset, treat data augmentation (sliding windows, synthetic jitter) as mandatory, and keep a simpler model (random forest/k-NN on the same features) as a fallback comparison in case the CNN overfits.

## 5.2 Mode accuracy vs traffic-type accuracy — report separately, never blended

| | Mode accuracy | Traffic-type accuracy |
|---|---|---|
| Task | Binary | Multi-class (3–6 classes) |
| Underlying signal | Near-deterministic structural offset | Statistical/behavioral pattern — noisier |
| Expected difficulty | Low | Moderate-to-high |
| Random-guess baseline | 50% | 1/(number of classes) |

## 5.3 Targets for "effective enough to demo"

- **Mode accuracy**: minimum acceptable 90%, target 97–99%. Because the signal is close to a fixed offset, anything in the 70–80% range signals a feature-extraction bug (e.g., padding/fragmentation masking the offset), not a modeling limitation — fix the pipeline before tuning the model.
- **Traffic-type accuracy (3 MVP classes — HTTPS/VoIP/ICMP)**: minimum acceptable 75–80%, target 85–90%.
- **Traffic-type accuracy (full 6-class roadmap set)**: expect a drop once WhatsApp-pattern media, email, and video are added, since these overlap more in coarse shape; a realistic target is 70–80%, with a confusion matrix reported alongside.

## 5.4 What to report, not just the headline number

- **Per-class precision/recall** for the traffic-type head — a model that's 90% "accurate" only because 90% of the test set is HTTPS and it defaults to guessing HTTPS is not actually working.
- **A confusion matrix** — more informative than one blended number, and it directly supports the AI Confidence Score output requirement: confidence should track *measured* per-class accuracy, not the model's raw self-reported certainty.
- **Held-out test accuracy only** — never quote training accuracy; with a small dataset it's close to meaningless.
- **A naive-baseline comparison** (always predict the majority class) for both heads — if the CNN only marginally beats this, that's the thing to fix before demo day.

---

**Two production notes that directly protect you against your own risk list:**
- **Have segment 5–8 pre-recorded as a fallback**, exactly as your risk table already proposes — but *record the fallback from a real run*, not a mockup, so if you have to cut to it, it's still a genuine result and not a fabricated one.
- **Keep segments 3–8 to under two minutes total** if this is a hackathon demo video with a time limit — the two beats worth protecting no matter what get cut are #6 (score collapse) and #8 (encrypted-only inference), since together they are the entire pitch in miniature: *we score configs, and we can do it even when we can't see the handshake.*
