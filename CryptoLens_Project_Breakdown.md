# CryptoLens — Full Project Breakdown
### Problem Statement Explained • MVP Plan Reviewed • Part 1 Implementation Guide

---

# PART 1: The Problem Statement, Explained From Zero

## 1.1 The Background, in Plain Terms

A **VPN (Virtual Private Network)** lets two points on an untrusted network (like the public internet) talk to each other as if they were on a private, secure wire. **IPsec** is one of the most common protocols used to build VPNs — it's what connects branch offices, secures government links, and underlies a lot of cloud-to-cloud traffic.

IPsec actually does its job in **two separate phases**, which is the single most important thing to understand before anything else makes sense:

### Phase 1 — IKE (Internet Key Exchange) — "the handshake"
Before any real data flows, two devices (call them Peer A and Peer B) need to:
- Agree on *which* encryption algorithm, hashing algorithm, and key-exchange method they'll use
- Prove who they are to each other (authentication)
- Generate a shared secret key that both sides know, without ever sending that key over the wire in the clear (this is done using **Diffie-Hellman**, or DH)

This negotiation happens in cleartext control packets (UDP port 500, or 4500 if NAT is involved). This is good news for an analyzer: **you can literally read the handshake and see exactly what algorithms and settings the two sides agreed to** — no decryption needed, because the negotiation *itself* isn't encrypted (only the identities/certain payloads may be, depending on IKE version).

### Phase 2 — ESP (Encapsulating Security Payload) — "the actual data"
Once the handshake is done, real traffic flows, wrapped in ESP packets (IP protocol 50). **This part is encrypted.** You cannot read what's inside — that's the whole point of IPsec. All you can see from the outside are things like:
- Packet sizes
- Timing between packets
- Source/destination (partially, depending on mode)

This is the second most important idea in the whole problem: **once you're only looking at ESP, you are blind to content, and can only infer things from patterns (metadata)** — you cannot "just read" the mode or the traffic type anymore. This is exactly why the problem statement wants an AI-based approach for this part — it's not a parsing problem anymore, it's a pattern-recognition problem.

### Tunnel Mode vs Transport Mode
This is a configuration choice made during the handshake, and it matters a lot for security:
- **Transport Mode**: only the original packet's *payload* is encrypted. The original IP header (real source and destination) stays visible. Typically used host-to-host.
- **Tunnel Mode**: the *entire* original packet (header + payload) is encrypted and wrapped inside a *new* IP header. This hides the real source/destination from anyone snooping on the tunnel. Typically used gateway-to-gateway (site-to-site VPNs).

Because tunnel mode wraps an extra IP header, tunnel-mode ESP packets are consistently a little bigger (roughly 20–40 bytes, depending on IPv4/IPv6) than transport-mode ones carrying equivalent data. That's the structural fingerprint the AI is meant to pick up on.

## 1.2 Why "Configuration Quality" Matters

IPsec being "on" doesn't mean it's secure. Two tunnels can look identical on the wire but have wildly different real-world security:

| Setting | Weak choice | Strong choice |
|---|---|---|
| Cipher | 3DES, AES-128-CBC | AES-256-GCM |
| Hash/Auth | MD5, SHA1 | SHA-256/384, or built into GCM |
| DH Group (key exchange) | Group 1/2 (768–1024 bit) | Group 14+ (2048-bit+) or elliptic-curve groups |
| PFS (Perfect Forward Secrecy) | Disabled | Enabled |
| Replay protection | Disabled/misconfigured | Enabled and verified working |
| Metadata exposure | Real IPs visible, sequential SPI numbers, identity sent in clear | Hidden/randomized |

A "secure-looking" tunnel using 3DES and a 1024-bit DH group is trivially breakable by modern standards, but a packet capture of it looks structurally identical to a properly configured one unless someone actually reads the handshake and checks these values against known-good baselines (like NIST SP 800-77 or NSA's CNSA 2.0 suite).

## 1.3 What the Problem Statement Is Actually Asking You to Build

Breaking down every bullet from your screenshots, mapped to what it *means*:

### (a) VPN Testbed Generation
> "Develop a laboratory environment capable of establishing IPsec VPNs using multiple configurations."

You need to actually **build real IPsec tunnels yourself**, in a lab, with knobs you control, covering combinations of:
- Tunnel Mode / Transport Mode
- AES-128, AES-256, AES-GCM, AES-CBC+HMAC (cipher/mode combos)
- Different DH Groups (weak and strong)
- PFS enabled/disabled
- IPv4 and IPv6
- Different application traffic riding on top: VoIP, WhatsApp, Email, Web-browsing, ICMP, Video streaming

This testbed is what gives you **ground truth** — you know exactly what config produced each capture, because you built it. This is essential: it's what lets you later *prove* your AI's inference is correct, because you can check its guess against the actual config you set.

### (b) Traffic Capture
> "Acquire network traces using tools such as Wireshark, TCP-dump, custom packet capture utilities."

Capture the IKE negotiation packets, the ESP data packets, and optionally AH packets (AH is an older, less-used IPsec mode that authenticates but doesn't encrypt — marked optional because most modern deployments use ESP only). This gives you the raw `.pcap` files that everything downstream operates on.

### (c) AI-Based Protocol Identification
> "Develop an AI engine capable of automatically identifying..."

This is the core "smart" part of the project. Given a capture (or live stream), automatically determine:
- **IPsec protocol** (ESP vs AH)
- **IKE version** (IKEv1 vs IKEv2)
- **Tunnel Mode vs Transport Mode**
- **Encryption algorithm**
- **Authentication algorithm**
- **Key exchange method** (which DH group)
- **Security Association (SA) characteristics** (the negotiated parameters bundled together — lifetime, sequence numbers, etc.)
- **Predict the type of traffic riding inside the ESP tunnel** (VoIP? Web? Video?) — **without decrypting it**

Critical nuance the problem statement is testing you on: **half of this list is deterministic (readable straight from the IKE handshake if you have it), and half of it is genuinely only inferable from encrypted traffic patterns.** A naive team will try to "AI" everything. A strong team will recognize that cipher/DH/auth-algorithm are *facts you can just parse* when the handshake is visible, and reserve the actual machine-learning/AI effort for the two things that are truly ambiguous from ciphertext alone: **mode** and **inner traffic type**.

### (d) Security Assessment
> "The framework should automatically evaluate..."

Turn the identified parameters into a judgment call about security posture:
- **Cryptographic strength** — is the cipher/hash combo modern and strong?
- **Configuration compliance** — does this match a recognized standard (NIST SP 800-77, NSA CNSA 2.0)?
- **Security Association parameters** — are SA settings sane (short-enough lifetimes, proper sequence number handling)?
- **Key lifetime** — how long before rekeying happens (too long = more exposure if a key is ever compromised)
- **Replay protection** — is the anti-replay window actually functioning (this can be *tested*, not just inferred, since you control the lab)
- **Forward Secrecy configuration** — is PFS on?
- **Cipher suite strength** — overall grading of the combination

### (e) Output
> "The output should include a comprehensive security score, traffic analysis, and metadata inference. Automatically generate..."

- **Executive Report** (short, for a manager — "your VPN is a 42/100, here's what to fix")
- **Technical Report** (long, for an engineer — exact values, exact clauses violated)
- **Risk Score** — a single number summarizing danger
- **Threat Matrix** — a table breaking risk down by category (crypto, key exchange, metadata, etc.), so someone can see *why* the score is what it is
- **AI Confidence Score** — since parts of the analysis are inferred rather than parsed with certainty, the tool should be honest about how sure it is

### Expected Deliverables (from the problem statement)
1. Working software prototype
2. AI classification engine
3. Interactive dashboard
4. Security assessment report
5. Demonstration video
6. Technical documentation
7. **Dataset used for training/testing** — this line is important and easy to under-read. It implies the evaluators expect an actual labeled dataset behind the AI component, the kind you'd use to *train or rigorously validate* a classifier — not just a handful of examples used to write prompts.

---

# PART 2: Honest Review of Your MVP Plan (v3)

## 2.1 What the plan gets right

**Architecture is sound and matches the problem statement's shape almost exactly.** You've correctly split control-plane (deterministic, parseable) from data-plane (inference-only), which is the single most important design decision in this entire problem — and a lot of teams will get this wrong by throwing everything at a model. Specifically:

- Cipher, DH group, PRF, IKE version, auth algorithm → parsed deterministically from the handshake AST. This **directly satisfies** the "encryption algorithm / authentication algorithm / key exchange method / SA characteristics" bullets when the handshake is visible, with 100% accuracy and zero AI cost. Good call, and a great thing to say out loud to judges — it shows you understand *when* to use AI and when not to.
- Tunnel vs Transport mode + inner traffic type → routed to the AI/inference path only, and **only** when the handshake isn't available. This precisely matches the "predict type of traffic inside ESP" and mode-inference bullets, and the "AI Confidence Score" output requirement maps cleanly onto your dashboard's confidence bar.
- The scoring formula (Section 5) is a genuinely good, defensible design: weighted sub-scores, each mapped to a named standard clause. This directly satisfies "cryptographic strength," "configuration compliance," "forward secrecy configuration," and "cipher suite strength" almost one-to-one.
- Replay protection is handled as an **active test** rather than a passive guess — this is actually a stronger answer to the "replay protection" bullet than most teams will give, since you're not inferring it, you're proving it.
- Section 9 (privacy) is a strong pre-emptive answer to an obvious judge question ("why send anything to an external API at all?").

## 2.2 The biggest structural risk: is this actually an "AI engine"?

This is the most important critique I can give you, so I'll be direct about it: **the plan's "AI" is prompt-engineering a general-purpose LLM API to read a list of numbers.** That can work, but it creates two real exposures:

1. **Deliverable #7 says "dataset used for training/testing."** Your plan does list a "labeled PCAP dataset," but its own text says it's used *"for testing the API prompts"* — not for training anything. If a judge asks "what did you train?", the honest answer right now is "nothing; we used a labeled dataset to validate prompts against a third-party model we don't control." That's a fair engineering choice, but it's a different claim than "AI classification engine," and if that gap surfaces live in front of judges without you having a ready answer, it reads as a weak spot rather than a scoping decision.
2. **Determinism/latency/dependency.** An external API call means your demo depends on network access to a third party during a live presentation — you've already flagged this risk yourself in Section 11, which shows self-awareness, but it doesn't remove the exposure, it just adds a fallback (cached results) that itself weakens the "we did it live" pitch if triggered.

**Concrete recommendation:** Build a small **local, trained classifier** (e.g., a decision tree, random forest, or even k-NN — nothing exotic) on your own labeled feature set (packet-length sequences, inter-arrival timing) for the tunnel/transport and traffic-type classification tasks. This is a well-trodden, defensible approach (this exact kind of ESP traffic fingerprinting is established in real security research), it directly satisfies "AI classification engine" *and* "dataset used for training/testing" without any asterisks, it removes your live-demo's dependency on external network access, and it's genuinely not much extra work since you're already generating the labeled features for the API prompts. You could keep the cloud API as an optional secondary/roadmap comparison ("look, we also tried this against GPT-class reasoning and here's how it compares") rather than as the load-bearing component.

## 2.3 Gaps against the problem statement, called out directly

| Problem statement asks for | MVP plan status | Verdict |
|---|---|---|
| IPv4 **and** IPv6 | IPv6 pushed to roadmap only | **Gap.** PS explicitly lists this as a required config variation, not a stretch goal. Even a single IPv6 tunnel demoed live would close this. |
| Traffic types: VoIP, **WhatsApp**, **Email**, Web-browsing, ICMP, **Video streaming** | MVP demos only 3 of 6 (HTTPS, VoIP/SIP, ICMP); WhatsApp-pattern, SMTP/IMAP, video all pushed to roadmap | **Gap.** Half the named traffic types are explicitly deferred. Reasonable for hackathon time constraints, but you should have a one-line answer ready ("we prioritized traffic types with the most distinct timing signatures to prove the classification approach works; the remaining types use the same pipeline, unchanged"). |
| Key lifetime evaluation | **Not present anywhere in the scoring formula (Section 5) or reporting.** | **Real gap, not just a scoping trade-off.** SA lifetime is a field you can literally read off the IKE proposal payload deterministically — cheap to add. I'd add either a bonus/penalty term to `M_score` or a standalone flag in the threat matrix ("SA lifetime exceeds recommended 8h/1GB rekey threshold"). |
| AH packets (optional) | Not mentioned at all | Fine — it's explicitly marked optional in the problem statement, so silence is an acceptable answer, but be ready to say "we scoped to ESP-only since that's the overwhelmingly dominant real-world deployment; AH support is a roadmap item." |
| "Dataset used for training/testing" as a deliverable | Present, but described only as prompt-testing data, not training data | **See 2.2 above — this is the one I'd fix first if you only fix one thing.** |
| Executive + Technical dual report | MVP is a single-page PDF; dual report is roadmap-only | Acceptable trade-off for hackathon time, just be transparent about it rather than implying both exist. |

## 2.4 What I'd add for "production ready," beyond hackathon scope

- **Local trained classifier as the primary inference path** (see 2.2) — single highest-value addition.
- **Deterministic key-lifetime extraction and scoring** — cheap, closes a real gap.
- **Confidence calibration, not just LLM self-reported confidence.** If you keep any LLM-based path, back the "confidence score" with an actual validation-set accuracy number per traffic class (e.g., "94% accuracy on held-out VoIP samples") rather than trusting the model's own stated confidence, which is not a reliable signal on its own.
- **Securing the tool itself**: nothing in the current plan discusses authenticating access to the dashboard, protecting the API keys used for the cloud calls, or TLS between the dashboard and backend. For a security-assessment tool, judges may specifically probe "how do you secure *this*?"
- **Audit logging** — who ran an assessment, when, against what tunnel — relevant for any tool marketed at enterprise/government/military use (Section 1's own framing).
- **Fleet/multi-tunnel view and historical trends** are already in your roadmap — keep them there, they're correctly scoped as post-MVP.
- **Config-weight profiles per compliance regime** (NIST vs CNSA vs ISO 27001) is also correctly deferred — good call, this is a real feature but not needed to prove the concept.

---

# PART 3: Part 1 — Testbed & Infra Lead, Explained in Full

## 3.1 What This Part Is, In Plain Terms

You are building **Stage 1** of the pipeline — the very first box in the architecture diagram. Nothing else in the project can be built or tested without your output, because everyone else needs **real, labeled packet captures** to work with. The dashboard team needs something to display. The scoring team needs real handshake data to parse. The AI/inference team needs real ESP traffic with known ground-truth labels to validate against. You are the source of truth for the entire project.

Concretely, your job is to answer the question: *"Can I, on a single machine, spin up two virtual computers that talk to each other over a real IPsec tunnel, with a specific configuration I choose, send realistic traffic between them, and record the exact packets that cross the wire — automatically, repeatably, and labeled?"*

### The three concepts you need to understand first

**1. strongSwan.** This is a real, production-grade, open-source implementation of IPsec (the same kind of software actual companies and governments run). Instead of hand-writing raw IKE/ESP packets yourself (extremely hard and error-prone), you configure strongSwan to be "Peer A" and another instance to be "Peer B," tell each one what algorithms to use, and it does the actual protocol work for you. Your configuration choices (which cipher, which DH group, tunnel vs transport, PFS on/off) are what strongSwan will faithfully implement — so your generated captures will reflect *real* protocol behavior, not a simulation of it.

**2. Docker + Linux network namespaces (netns).** You need *two separate* network identities for Peer A and Peer B — if they were both just "localhost," the tunnel wouldn't mean anything (there'd be no real network path for IPsec to protect). A **network namespace** is a Linux feature that lets you create an isolated, virtual network stack — effectively a second "fake computer" with its own IP address and network interfaces — without needing a second physical machine or even a second full VM. Docker is used to package strongSwan (and its dependencies) into a container so it's easy to spin up, tear down, and reproduce identically on any machine (including judges' laptops during the demo, if it comes to that). Together: Docker gives you reproducible software, netns gives you a plausible network topology.

**3. Jinja2 templating.** strongSwan's configuration file format (`swanctl.conf`) is just a text file with sections and key-value pairs. Rather than hand-writing six-plus separate config files (one per configuration you're testing), you write **one template** with placeholders (e.g., `{{ cipher }}`, `{{ dh_group }}`, `{{ pfs }}`) and a small script fills in those placeholders from a list of parameter combinations. This is exactly how the "6 core configs" from the MVP plan get generated without manual duplication — and, importantly, it's exactly the pattern the roadmap's "full config matrix" (all 6 DH groups, IPv6, PQC) will scale into later, with zero rewrite of the templating logic.

## 3.2 File-by-File Breakdown

```
testbed/
├── docker/
│   ├── Dockerfile.strongswan
│   └── netns-setup.sh
├── configs/
│   ├── template.swanctl.conf.j2
│   ├── config_matrix.yaml
│   └── generate_configs.py
├── traffic_gen/
│   ├── https_client.py
│   ├── voip_sim.py
│   └── icmp_ping.py
├── replay_test/
│   └── inject_duplicate_esp.py
└── run_capture_session.sh
docker-compose.yml   (shared ownership)
```

### `docker/Dockerfile.strongswan`
**What it is:** The recipe for building a container image that has strongSwan (and any tools you need alongside it — `tshark`, `iproute2`, etc.) pre-installed.
**Why it exists:** So that "having strongSwan set up correctly" is a one-time solved problem, not something every teammate (or the judges' machine) has to redo by hand.
**Connects to:** `docker-compose.yml`, which will reference this Dockerfile to build the actual running container(s).

### `docker/netns-setup.sh`
**What it is:** A shell script that creates two (or more) Linux network namespaces — think of them as "Peer A's network" and "Peer B's network" — and wires them together with a virtual Ethernet link (`veth` pair), giving each a distinct IP address.
**Why it exists:** This is what makes the IPsec tunnel *mean something*. Without two distinct network identities, there's no "untrusted network" for IPsec to protect traffic across.
**Connects to:** Runs before strongSwan starts inside each namespace. `run_capture_session.sh` will call this early in its sequence.

### `configs/template.swanctl.conf.j2`
**What it is:** A single Jinja2-templated strongSwan configuration file, with placeholders for the variable parts (cipher, DH group, mode, PFS on/off).
**Why it exists:** One source of truth for "what does a valid strongSwan config look like," parameterized instead of duplicated six-plus times.
**Connects to:** Read by `generate_configs.py`, which fills it in per row of `config_matrix.yaml`.

### `configs/config_matrix.yaml`
**What it is:** A plain data file (YAML) listing every configuration combination you want to test — e.g., one row per (mode, cipher, DH group, PFS) combination, matching the MVP's "6 core configs."
**Why it exists:** Keeps "what configurations exist" as data, not code — anyone can add a 7th row later (this is exactly how the roadmap's "full config matrix" will eventually scale, without touching the template or the generator script).
**Connects to:** Read by `generate_configs.py`. This file is also your **ground-truth label source** — every capture you produce should be traceable back to exactly one row here, since that's what lets the AI/scoring teams later check "did the model correctly guess this was Tunnel Mode + AES-256-GCM?" against something real.

### `configs/generate_configs.py`
**What it is:** A Python script that reads `config_matrix.yaml`, and for each row, renders `template.swanctl.conf.j2` into a real, ready-to-use `.conf` file (e.g., `config_01_tunnel_aesgcm_dh19_pfson.conf`).
**Why it exists:** Automates config generation so you're not hand-editing six-plus files, and so adding new rows to the matrix costs zero extra manual work.
**Connects to:** Output feeds directly into strongSwan when it starts up inside the container/namespace for that specific test run.

### `traffic_gen/https_client.py`
**What it is:** A script that makes real HTTPS requests (e.g., via `curl` or Python's `requests`) across the tunnel, to generate realistic web-browsing traffic patterns (bursty, request/response, TLS-sized packets).
**Why it exists:** The AI's "predict inner traffic type" task needs *real* traffic shapes to learn/be tested on, not made-up numbers.
**Connects to:** Its traffic gets captured by `tshark` as part of `run_capture_session.sh`, and the resulting packet-length/timing sequences become training/testing features for the inference stage (owned by other teammates).

### `traffic_gen/voip_sim.py`
**What it is:** Uses **Scapy** (a Python packet-crafting library) to simulate a VoIP/SIP call — regular, small, evenly-timed UDP packets, mimicking how a real voice call's RTP stream behaves.
**Why it exists:** VoIP has a very distinctive fixed-size, fixed-interval fingerprint, very different from bursty web traffic — this is one of the clearest signals the inference stage will use.
**Connects to:** Same as above — feeds the capture pipeline.

### `traffic_gen/icmp_ping.py`
**What it is:** Sends simple ICMP echo (ping) packets across the tunnel.
**Why it exists:** ICMP is the simplest, most uniform traffic pattern — a good baseline/sanity-check case for the classifier (if it can't get ICMP right, nothing else will work either).
**Connects to:** Same capture pipeline.

### `replay_test/inject_duplicate_esp.py`
**What it is:** A script that captures a legitimate ESP packet crossing the tunnel and deliberately re-sends (replays) a duplicate of it.
**Why it exists:** This directly implements the problem statement's "replay protection" evaluation — but as an **active test** rather than a guess. A correctly configured tunnel should detect and drop the duplicate (strongSwan's anti-replay window); if it doesn't, that's a real, provable finding, not an inference.
**Connects to:** Its outcome (packet accepted vs dropped) becomes a boolean flag reported directly on the dashboard/report ("Replay protection: confirmed / failed"), independent of the AI pipeline entirely.

### `run_capture_session.sh`
**What it is:** The orchestrator. In sequence, it: brings up the network namespaces, starts strongSwan with a chosen generated config, brings the tunnel up, starts `tshark` capturing on the relevant interface, runs the traffic generators (and optionally the replay test), stops the capture, and saves a labeled `.pcap` file.
**Why it exists:** This is what makes the whole testbed "one command, repeatable" rather than a manual, error-prone sequence of steps every time you want a new capture.
**Connects to:** This is the script that gets run once per row in `config_matrix.yaml` (possibly looped, or called by `docker-compose.yml`), and its output — labeled `.pcap` files — is the **single deliverable that everything else in the project consumes.**

### `docker-compose.yml` (shared ownership)
**What it is:** The top-level file that ties the container(s), namespaces, and volumes together so the whole testbed can be started with `docker-compose up`.
**Why it exists:** Matches the MVP plan's stated deployment goal directly ("`docker-compose up` — single command").
**Connects to:** Everything above. It's the front door to your entire subsystem.

## 3.3 How Your Output Plugs Into the Rest of the Project

Your deliverable, concretely, is a folder of **labeled `.pcap` files** — one (or more) per configuration/traffic-type combination — where the label is derivable from the filename or an accompanying manifest (e.g., a small JSON/CSV mapping filename → the exact row in `config_matrix.yaml` used to produce it). A naming convention like:

```
captures/tunnel_aes256gcm_dh19_pfson_https.pcap
captures/transport_3des_dh2_pfsoff_voip.pcap
```

...means anyone downstream can look at a filename and know the ground truth without having to ask you. This single convention is what makes:
- **Stage 2 (Capture & Demux)** possible — they split your `.pcap` into control-track (UDP 500/4500) and data-track (proto 50) packets.
- **The AI/inference team's validation** possible — they can only prove their model correctly inferred "Tunnel Mode, VoIP traffic" if they know, independently, that's actually what was in that file.
- **The scoring engine's testing** possible — they need real handshakes with real (sometimes deliberately weak) parameters to confirm the scoring formula produces the right verdicts.

## 3.4 Suggested Order of Attack (Beginner-Friendly Path)

1. **Get one strongSwan tunnel working manually first**, no automation — two Docker containers, hand-written config, verify with `ipsec status` / `swanctl --list-sas` that a tunnel actually forms. Don't template anything yet. This is the "does this even work at all" checkpoint.
2. **Add network namespaces** so the two peers are genuinely on separate virtual networks rather than the same Docker bridge, and confirm the tunnel still comes up.
3. **Capture your first `.pcap` by hand** with `tshark` while pinging across the tunnel — confirm you can see IKE packets in the clear and ESP packets that are unreadable. This proves your understanding of the two-phase model in Section 1.1 is correct in practice, not just in theory.
4. **Write the Jinja2 template** for the one config you already have working, and confirm `generate_configs.py` reproduces the exact same file you hand-wrote.
5. **Build out `config_matrix.yaml`** with the remaining rows, and confirm each renders correctly.
6. **Add the traffic generators** one at a time (ICMP first — simplest — then HTTPS, then VoIP), confirming each produces visibly different packet patterns in Wireshark before moving to the next.
7. **Wire it all into `run_capture_session.sh`** so one command produces one labeled capture end-to-end.
8. **Add the replay test last** — it's the most self-contained piece and doesn't block anything else.
9. **Loop the whole thing across the config matrix** to produce your final labeled dataset — this is the artifact you hand off, and it's also literally the "labeled PCAP dataset" deliverable from Section 10 of the MVP plan.

