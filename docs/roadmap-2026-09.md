# Replicant roadmap, 2026-09

Produced by a five-persona debate on 2026-09-01 (CISO, Detection Engineer, Threat
Researcher, SOC Operations Leader, and CPO as chair), run as a workflow: each principal
filed positions grounded in the real code, the four domain experts cross-examined the whole
pool, and the CPO resolved the debate and cut everything that could not be defended across
disciplines. 27 proposals in, 16 survived, 7 notable cuts recorded below.

This is a decision record on the same terms as `docs/10x-roadmap-triage.md` and
`docs/round3-expansion-triage.md`: what belongs here is the decision, not a commitment to
build on a date. Nothing here is implemented yet. The full per-agent debate is in the
workflow journal for the run that produced this (not in the repo by design).

## The keystone

The room did not actually split five ways; it split along four seams, and the four domain experts agreed with each other far more than the proposal count suggests. My job as chair was to stop that agreement from producing a 20-item wish list and force it down to the few things that change what Replicant IS.

THE ELEPHANT, and it settled everything else. Every principal championed the same fact from a different seat: the headline promise, "exercises the matching detection," has never once been observed end to end. Every timing and delivery claim is loopback-only, and the project's own record shows we are one transposed IP octet (10.0.20.125 vs 10.20.0.125) from "nothing arrives." #27, #21, #2 are the same truth at product, ops, and positioning altitude. I ruled this the keystone: the lab test stops being sequencing step 2 and becomes a hard launch gate, external positioning holds at "generates vendor-accurate CEF, detection-unverified" until first observed rule fire, and "first observed fire" is the activation milestone. This is not negotiable and it re-ranks the whole board: anything that adds surface before the pipe is proven loses to anything that proves or honestly scopes it.

FIDELITY vs SAFETY (the marker). #1/#17 collided with the codebase's own "preserve fidelity, marker off by default" stance. I resolved it fast because the fidelity objection collapsed under scrutiny: both fidelity leads (DE, TR) conceded flexString1 is an unused flex slot no shipping detection keys on, so marking it corrupts nothing a rule reads. The fidelity default is right for --to-file golden validation and wrong for a live shared collector where analyst de-confliction outranks a slot no rule reads. #1 folds into #17's crisp destination-conditional form; #3 (attestation) and #5 (deployment boundary) ride with it as one safety workstream, and it must land before any live pilot or the pilot burns the shift it serves.

COVERAGE APPETITE vs PRODUCT FOCUS. This was the real fight, DE+TR pushing five new-telemetry builds (#13 TLS/JA3, #14 T1105+HTTP, #15 tool profiles, #16 infra metadata, #10 tactic gaps) against CISO+me pushing back on scope before the delivery path is proven. I drew one line and applied it everywhere: PROVE THE PIPE BEFORE WIDENING THE CATALOG. The fidelity leads WIN on every item that needs no live SIEM and adds no unverified surface (#7 transferability, #11 statistical fidelity suite, #9 the FP topologies that actually break the aggregation key, #12 the diurnal envelope) and LOSE on every item that bolts a new field class onto three vendors, two of them appliance-less and [Unverified], before we have watched one rule fire (#13, #14 builds, #15, #16). Notably TR killed their own #13 scope on exactly this reasoning, and SOC downgraded their own #20 sweep as premature. That is a healthy room.

THE HONESTY CLASH (#7 vs #16). The sharpest genuine contradiction: #16 wants to synthesize a domain registration-age field so REP-020 stops collapsing into REP-008, while #7 warns that a synthetic age is precisely NOT what PREDATOR keys on, so a green result would lie. Both cannot ship. I ruled for #7: fabricating enrichment the reserved TLDs cannot legitimately carry manufactures the exact false confidence the whole project's "state what it does not prove" ethic exists to prevent. The honest move is the parser-only label, not the fake field. #16 is cut, its honest intent absorbed into #7.

OPS-NOISE vs THE CLEAN MODEL. SOC's #18/#19 exposed that the clean synthetic stream is a demo artifact: an analyst reverse-engineers pivots from a raw manifest (the exact toil the tool sells against), and pass/fail is a CI signal not the MTTD leadership reports upward. Both survive, but #19 carries a hard guard I imposed over the room: it measures offline rsyslog-to-detection latency and must be labeled "offline pipeline latency," never "production MTTD," or it reproduces the overselling #2 exists to fix.

THE FORK I REFUSED TO LEAVE OPEN (#24). I will not sign a roadmap on an unresolved identity. The recorded "personal lab, not customer delivery" is contradicted by the shipped surface (React UI, installer matrix, three vendor profiles, public wheels) and that ship has sailed. I resolve it on the record: Replicant is an OSS detection-as-code product for detection engineers, CLI-first, web optional. That decision is what makes #23 (pip), #25 (Action), #22 (flightsim), #26 (vendor honesty) table stakes rather than scope creep, and it is why they sequence behind the gate, not ahead of it.

Net: a short roadmap that proves and honestly scopes the core claim, ships the two ops surfaces that make an analyst reach for the tool twice, and hardens fidelity with tests instead of new unverified fields. Everything that widens the catalog waits behind the first observed rule fire.

## Roadmap (survivors)

### Now (decisions and cheap, high-leverage)

**1. Elevate the LogRhythm lab test to a hard launch gate; scope every external claim to generator-verified / delivery-unverified until first observed rule fire**  _(effort: small)_

- Why it survived: Unanimous champion across all five seats (#27/#21/#2). The headline promise has never been observed end to end; the whole verification story is being built on a send path nobody has watched work. This is a decision plus a positioning edit, not a build, so it costs a paragraph and protects the one asset a safety tool cannot rebuild once a hostile reviewer finds the gap in minutes.
- Champions: CPO (#27), CISO (#2/#27), Detection Engineer (#2/#27), Threat Researcher (#2/#27), SOC Ops (#21/#27)
- Opposition and resolution: No opposition to the direction. The only latent tension was with the codebase's polish instinct to keep shipping features; I ruled the gate outranks the backlog: no feature-quarter is spent before the gate clears, and 'first observed rule fire' becomes the activation milestone.
- Product rationale: It converts a demo into a product with an honest maturity claim, and it is the single highest-leverage act available because it re-ranks everything below it. Applying the project's own banned-the-word-'verified' discipline to the top-line claim is the cheapest credibility insurance we will ever buy.

**2. Resolve the identity fork on the record: OSS detection-as-code product for detection engineers, CLI-first**  _(effort: small)_

- Why it survived: CPO's own meta-decision (#24), championed by CISO and SOC. Every prioritization call, including the already-adopted F2/F5/F1 set, answers differently depending on this fork, and the shipped surface (React UI, installer matrix, three profiles, public wheels) has already made the choice de facto.
- Champions: CPO (#24), CISO (#24), SOC Ops (#24)
- Opposition and resolution: TR and DE noted their fidelity backlog is the priority under the 'personal lab' reading. I resolved toward OSS because the public surface is irreversible and the detection-as-code positioning (F2, the Action, flightsim contrast) only coheres under it; the fidelity work survives on its own merits regardless of the fork, so nothing is lost by settling it.
- Product rationale: A decision, not code, and the cheapest highest-leverage item in the set. It is the gate on whether #23/#25/#26 are table stakes or scope creep, and I will not underwrite a roadmap that leaves it ambiguous.

**3. Conditional synthetic marker default-on for non-loopback sends, plus a manifest attestation field and a 'detection lab, not production SIEM' deployment boundary**  _(effort: medium)_

- Why it survived: The single control that keeps Replicant from being banned the first time it burns a shift (#17/#1), championed by CISO and SOC from the audit and de-confliction angles simultaneously. It reuses the existing uniform _mark choke point; only the default and a destination check change. #3 (one-line attestation persisted in the manifest) and #5 (deployment-boundary doc) fold in as the governance layer that makes the marker coherent.
- Champions: SOC Ops (#17), CISO (#1/#3/#5)
- Opposition and resolution: The fidelity default ('marker off to preserve fidelity') was the standing objection. Both fidelity leads conceded flexString1 is an unused slot no detection reads, so the fix is destination-conditional: OFF for --to-file and loopback where the golden line is the oracle, ON for non-loopback with --no-marker as an explicit logged override. Fidelity and safety both kept.
- Product rationale: An enterprise will not approve an unattested attack-log injector near a production pipeline. This turns '3am fake attack incident' into an authorized, auditable, reversible test, and it is the hard precondition for the rank-4 pilot.

**5. Per-technique validation-transferability catalog property (transfers-to-production vs parser-only)**  _(effort: small)_

- Why it survived: The rare item all four domain experts championed (#7). REP-011 fires on a synthetic srccountry tag while the production rule joins real GeoIP/ASN to an IdP identity; REP-020 cites a domain-age detector under a reserved TLD with no registration date; REP-016 DGA sits under .invalid. A green result on those exercises the parser, not the shipped rule.
- Champions: Detection Engineer (#7), CISO (#7), Threat Researcher (#7), SOC Ops (#7)
- Opposition and resolution: Directly contested #16, which wanted to fabricate the missing enrichment fields instead. I ruled for #7: a synthetic registration-age is not what PREDATOR keys on, so manufacturing it produces exactly the false confidence this label exists to prevent. The honest half of #6 (the second-resolution eventtime ceiling) also folds in here as a disclosed per-technique limit.
- Product rationale: Coverage honesty at catalog granularity for near-zero effort. It tells an engineer BEFORE they spend a validation cycle whether a technique transfers, which is the difference between an operations asset and a parser test dressed as one.

**12. Name the flightsim wedge in positioning: zero-wire, log-strings-only, single fail-closed egress**  _(effort: small)_

- Why it survived: Broad support (#22). AlphaSOC flightsim is the tool a detection engineer actually reaches for to test network detections, and it emits real traffic to real infra. That is precisely the axis where Replicant is stronger and safer, and it appears nowhere in the repo's prior-art comparison.
- Champions: CPO (#22), CISO (#22), Detection Engineer (#22), Threat Researcher (#22), SOC Ops (#22)
- Opposition and resolution: No opposition; it is honest positioning at near-zero cost, told to the one audience that already knows the alternative.
- Product rationale: The safety model IS the differentiator, and we are not telling that story. A row in the prior-art table and a lead line in the pitch, contrasting same-detections-exercised against none-of-the-wire-risk.

**13. Reframe PAN-OS and Check Point as beta / community-verify ask; lead with 'FortiGate, verified' as the trust anchor**  _(effort: small)_

- Why it survived: Championed by CISO, backed by all (#26). Field-for-field fidelity is the credibility claim, yet only FortiGate is confirmed and the other two ship [Unverified] as silent equal peers, diluting the one thing that makes the tool trustworthy.
- Champions: CISO (#26), CPO (#26), Detection Engineer (#26), Threat Researcher (#26), SOC Ops (#26)
- Opposition and resolution: No opposition; complements the already-settled rejection of adding MORE vendors. Converts a standing liability into a contribution path.
- Product rationale: It is the same disclosure ethic the codebase holds itself to, and the cheapest realistic way to actually clear the [Unverified] markers: a community appliance owner, not a lab purchase we cannot make.

### Next (build, behind the gate)

**4. Run the minimal operational pilot as the adoption gate: REP-001, one detection, in the lab SIEM, marker-first, measured for delivery and latency**  _(effort: medium)_

- Why it survived: Championed by SOC and DE (#21) as the concrete execution of the rank-1 gate. A generator that works on loopback and has never fired a rule in a real SIEM is a demo; this is the run that changes that.
- Champions: SOC Ops (#21), Detection Engineer (#21)
- Opposition and resolution: No opposition; the only contested point was ordering, which I fixed into the entry: the rank-3 marker de-confliction MUST land before the pilot, or the pilot burns the shift it is meant to serve.
- Product rationale: This is proof-of-value, not a feature. Until it passes, the honest posture to leadership stays 'validated for log generation, unvalidated for detection assurance.' It is the event the entire roadmap is sequenced around.

**6. Statistical fidelity-regression suite: assert each technique's emitted stream satisfies the quantitative property it claims**  _(effort: medium)_

- Why it survived: Championed by DE, TR, and CISO (#11). shannon_entropy already exists unused; REP-004 claims >3.5 bits/char with nothing measuring it; byte-per-packet is a constant out_b//150 fingerprint a real analyst spots. Offline, deterministic, needs no SIEM, and catches the exact failure F2 cannot see: a rule firing on a stream that is nothing like real traffic.
- Champions: Threat Researcher (#11), Detection Engineer (#11), CISO (#11)
- Opposition and resolution: No opposition; explicitly distinguished from adopted F2 (F2 asks whether a rule fired, this asks whether the telemetry resembles the wire). Sequenced NEXT so it lands alongside the offline F2 tier it complements.
- Product rationale: It converts 'anchored to a paper' from an assertion into a checked property, the same way the golden oracle does for wire format. It is the class of evidence we can produce HERE while the lab test cannot yet run, so it strengthens the credible half of the claim without waiting on hardware.

**7. Per-run analyst validation card for single-technique runs**  _(effort: small)_

- Why it survived: Championed by DE and SOC (#18) as the day-one workflow F1/F2 do not touch. After an ad-hoc run the analyst reverse-engineers pivot entities, window, and expected rule from a raw manifest, which is precisely the manual toil the tool sells against. The advisory scaffolding and every field (objective, ndr_rule, ndr_uc, cef_fields, emitted window under --pace plan) already exist.
- Champions: Detection Engineer (#18), SOC Ops (#18)
- Opposition and resolution: No opposition. TR noted it is the right surface to carry the rank-5 transferability note, which I adopted: the card states what the run does and does not prove.
- Product rationale: A copy-pasteable SIEM search is the difference between a tool an analyst reaches for a second time and one abandoned after two frustrating runs. Low effort against existing scaffolding, high adoption leverage.

**8. Human-authored reference detection spec per technique, phased (pilot + transferable techniques first)**  _(effort: large)_

- Why it survived: Championed by SOC and TR (#8). Blueprint differentiator 5 promises 'telemetry and detection ship together,' yet the ndr_rule/ndr_uc labels have zero rule content behind them and a one-sentence hypothesis is not a spec you can build a rule from. This is the product's own headline promise, currently hollow.
- Champions: SOC Ops (#8), Threat Researcher (#8), CISO (#8 scoped), Detection Engineer (#8)
- Opposition and resolution: CISO flagged 24 specs upfront as large effort against an unproven core. Resolved by phasing: author the REP-001 spec as the artifact the rank-4 pilot needs, then the rank-5 transferable techniques, then expand only after first observed fire. It stays written documentation, respecting the standing no-auto-authoring / no-Sigma-generator constraint.
- Product rationale: It closes the promise-versus-delivery gap on the blueprint's own differentiator and gives the rank-7 card something authoritative to point at. Phasing keeps the large cost proportional to proven value.

**9. Two structural false-positive foils: shared-IP fan-in and NAT/proxy source-collapse**  _(effort: medium)_

- Why it survived: Championed by DE, TR, and SOC (#9). The current foils and adopted F5 add benign VOLUME but never break the aggregation KEY, which is exactly where REP-006/012/024 and REP-007/011 fail in production. REP-006's 'foil' is confirmed to be benign_external concatenated, which is not a foil at all. An analyst cannot set REP-007's per-source spray threshold honestly without a NAT-collapsed source in the data.
- Champions: Detection Engineer (#9), Threat Researcher (#9), SOC Ops (#9)
- Opposition and resolution: CISO neutral, deferring the build call to the detection lane; no opposition. Distinguished from generic background noise and from the rejected multi-source telemetry work, so it does not reopen a settled rejection.
- Product rationale: Two named, buildable, synthetic-safe generators cutting across five-plus techniques are worth more to real tuning than any ninth beacon variant. This is the difference between a threshold that survives go-live and one that pages the shift on day one.

**10. Scope the adopted F5 continuous baseline with a diurnal / work-week envelope**  _(effort: medium)_

- Why it survived: Broad support (DE, TR, CISO, SOC) on #12. Foils co-located in the run's short anchor make time-of-day a free discriminator, and they make the weak-periodic cases (REP-012/015) artificially EASIER than production, defeating the very difficulty those techniques exist to model.
- Champions: Threat Researcher (#12), Detection Engineer (#12), SOC Ops (#12), CISO (#12)
- Opposition and resolution: TR pushed to drop the elaborate per-host behavioral profiles as YAGNI until a technique needs them; I adopted that trim, keeping only the diurnal/work-week envelope. This refines an already-adopted item rather than adding scope.
- Product rationale: F5 as triaged reads as flat background noise, which reintroduces the too-clean problem it exists to remove. Scoping it correctly now is cheaper than shipping flat noise and re-cutting it later.

**11. Add offline-pipeline latency to the F2 verdict, strictly labeled (not 'production MTTD')**  _(effort: medium)_

- Why it survived: Championed by SOC and CISO (#19). The offline tier already knows emit-time and match-time, so the delta is nearly free, and latency regression is a real detection-quality signal F2's pass/fail misses. It gives the deferred F6 scorecard a real number to draw instead of re-counting the catalog.
- Champions: SOC Ops (#19), CISO (#19), Detection Engineer (#19), Threat Researcher (#19 conditional)
- Opposition and resolution: TR opposed unless it is never dressed as an operational metric, and DE set the same condition. I made the guard load-bearing: it measures local rsyslog-to-detection latency, must be labeled 'offline pipeline latency,' and gated on --pace plan, or it repeats exactly the loopback-claiming-to-be-production overselling that rank-1 exists to stop. Depends on F2 landing first.
- Product rationale: MTTD is the number leadership reports upward. Capturing it offline for near-free is high value; the labeling discipline is what keeps it honest rather than the next thing we have to walk back.

**14. Ship a pip-installable CLI (web as optional extra) and a container image**  _(effort: medium)_

- Why it survived: Broad support (#23), unblocked by the rank-2 OSS decision. The only documented install path is git-clone plus an npm React build, and CLI-only users pay the web UI's Node 18 floor at install time (Debian 12 / Ubuntu 24.04 / RHEL 9 all fail that build). A CLI-first evaluator will not build a React bundle to see one FortiGate line.
- Champions: CPO (#23), Detection Engineer (#23), Threat Researcher (#23), SOC Ops (#23)
- Opposition and resolution: CISO neutral, contingent on the identity fork; resolving rank-2 to OSS makes this table stakes rather than scope creep. Decouples the CLI from the web toolchain so CLI users stop paying for a UI they never open.
- Product rationale: Distribution is a product decision, not a release chore, and the current front door filters out the exact user we want. 'pip install replicant' plus a 60-second container trial is the adoption wedge for a CLI-first buyer.

### Later

**15. Position F2 as 'unit tests for your firewall detections'; ship the GitHub Action after F2 produces real verdicts, offline-scoped**  _(effort: medium)_

- Why it survived: Championed by SOC and DE (#25). Detection-as-code teams live in CI, and gating a build when a detection stops firing is a category none of Atomic/CALDERA/Attack Range/flightsim occupy.
- Champions: SOC Ops (#25), Detection Engineer (#25), CPO (#25), CISO (#25 conditional)
- Opposition and resolution: TR opposed shipping the marketplace Action ahead of proof. I split the item: adopt the positioning now (it costs words), but the Action ships LATER, only after F2 produces real verdicts, with its claim scoped to offline regression and never implying production SIEM assurance.
- Product rationale: The positioning reframes Replicant from 'a log generator' to 'the CI gate for detection content,' a genuinely open category. Splitting the artifact from the claim keeps us from shipping a go-to-market wrapper around an unproven pipeline.

**16. Gate the next catalog expansion on the tactic-gap tally; weight the deferred coverage scorecard by tactic**  _(effort: small)_

- Why it survived: Broad support (#10) as backlog-prioritization guidance needing no live verdicts. The tally is real: 12 Command-and-Control entries against 1 Impact, with at least eight beacon/callback variants, while network-visible Impact and cloud-exfil sit near zero.
- Champions: Detection Engineer (#10), Threat Researcher (#10), SOC Ops (#10), CISO (#10)
- Opposition and resolution: Everyone agreed it is downstream of the coverage scorecard the triage deliberately deferred until F2 produces real numbers. Kept as a recorded rule, not a build; the prevalence-basis documentation from #14 folds in here.
- Product rationale: A ninth beacon variant has near-zero marginal coverage value. Recording the tactic-weighted rule now means the eventual expansion is prioritized by gap, not by which paper had measured results, without committing a slot today.

## Rejected (the record, so a cut is argued rather than rediscovered)

- **#13 Encrypted-traffic fingerprinting surface (SNI, cert CN, JA3/JA4/JARM)** ; Prove the pipe before widening the catalog: a large new field class across three vendors, two appliance-less and [Unverified], added before one rule has been watched firing. TR killed their own scope here, and a 'structurally valid' synthetic JA3 that is not a real implant's hash reproduces the REP-011-srccountry trap. Revisit only after first observed fire and confirmed FortiGate SSL-inspection output.

- **#14 T1105 Ingress Tool Transfer + genuine HTTP transaction log path (as builds)** ; The HTTP path is a real hollow spot (T1071.001 ships as a bare IPS label with nothing to parse) and is the first thing to revisit post-gate, but both are large builds behind the launch gate. The cheap, honest slice, stating the catalog's prevalence basis, is folded into the rank-16 tactic-gap rule; the builds wait.

- **#15 Named on-wire tool profiles (--profile cobaltstrike-default)** ; Defensible and genuinely distinct from the rejected F7 re-ordering, but a medium preset layer downstream of proving the base techniques deliver end to end. Returns with the rank-8 reference specs once the pipe is proven and only for signatures published defensive docs can verify.

- **#16 Synthesize ASN / registration-age / fast-flux adversary metadata** ; Lost head-to-head to #7. Fabricating a domain registration-age the reserved TLDs cannot legitimately carry manufactures the exact false confidence #7's parser-only label exists to prevent, because a synthetic age is not what PREDATOR keys on. Honest labeling beats fake enrichment.

- **#6 Widen eventtime to sub-second resolution** ; DE opposed the fix from inside the domain: syslog preserves send ORDER regardless of eventtime resolution, and virtually all firewall/SIEM correlation windows are second-or-coarser. Do not widen a documented invariant speculatively ahead of the owed lab pass; the honest ceiling is disclosed per-technique via rank-5, and real FortiOS resolution is confirmed in the lab, not guessed.

- **#20 Threshold-sweep tuning mode** ; The owner (SOC) downgraded it themselves. It automates tuning on top of an F2 verdict pipeline that has never produced a real verdict and reference specs (rank-8) that do not yet exist to anchor the boundary. Premature; revisit after F2 verdicts and the specs land.

- **#4 Sign release wheels + CycloneDX SBOM** ; CISO cut their own item on their own sequencing test: provenance infrastructure for a hypothetical enterprise reviewer, for a tool never observed delivering a detection and whose OSS identity was until now unsettled. Keep only the near-free SHA256SUMS slice; defer signing and SBOM until after the gate clears.

## Standing constraints this roadmap respects

- The safety invariants (single fail-closed egress, synthetic entities, log-strings-only,
  eps cap, manifest per run) are not up for debate and none of the above touches them except
  to strengthen disclosure.
- The settled licensing/positioning constraints hold: never claim CEF certification or
  ArcSight validation; no Switzer; dark-only Factory UI; no new heavyweight runtime deps.
- Items already decided in `docs/10x-roadmap-triage.md` (F2 adopted, F5 adopted, F1 contract
  adopted; live SIEM adapters / Sigma parser / STIX packs / multi-source / more vendors
  rejected; scorecard deferred) are not reopened here except where an item explicitly refines
  one (10 scopes F5's baseline; 11 extends F2's verdict; 16 weights the deferred scorecard).

