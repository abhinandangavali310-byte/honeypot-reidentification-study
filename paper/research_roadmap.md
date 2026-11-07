# Research Roadmap: Privacy Leakage in Multi-Organization Honeypot Threat Intelligence Sharing

 
**Core question:** Does anonymized honeypot-generated threat intelligence still leak identifying information about the deployment site/organization when shared in a community threat-sharing model (CIAS Honey-Community style)?

> ### ⚠️ IMPORTANT NOTE — ALL DATA MUST BE REAL, NOT SIMULATED
> Every dataset used in this project must come from a real, publicly documented honeypot deployment — no synthetic/simulated organizations, no fabricated sessions, no artificially injected fingerprints. This roadmap has been rebuilt around a genuinely real, currently available dataset (identified below) that already contains the exact ground-truth structure this study needs. Nothing in Phase 1 onward should involve generating fake data.

> ### 🔄 MAJOR FINDING (Phase 3, completed) — CONTRIBUTION REFRAMED
> Initial row-level EDA suggested strong site-level fingerprinting (protocol mix looked very different per site). Rigorous evaluation using GroupKFold-by-attacker-IP showed this collapses to at/below the majority-class baseline (Tier A: 36.3%, Tier B: 31.8%, vs. 40.1% majority-class baseline). Root cause confirmed: 99.5% training accuracy vs. 37% test accuracy = severe overfitting to individual attacker identities, not genuine site fingerprints. Fold-level accuracy tracks almost perfectly with single-attacker concentration in that fold (Fold 1: one IP = 70% of fold → 14.3% accuracy; Fold 5: most diffuse fold → 46.5% accuracy).
>
> **The paper's core contribution is now:** naive (non-attacker-grouped) evaluation of shared honeypot data overstates site re-identification risk, because apparent fingerprints are driven by a small number of extreme-volume attackers rather than durable site-level signal. Phase 4 is reframed accordingly (see below) — from "test mitigations against a leak" to "quantify how much naive evaluation overstates the leak."

> ### ✅ PHASE 3 & 4 COMPLETE — FINAL NUMBERS
> | | Naive K-fold | GroupKFold (by attacker) | Overstatement |
> |---|---|---|---|
> | Majority-class baseline | — | — | (40.1%) |
> | Tier A (protocol/port retained) | 83.1% | 36.3% | **46.8 points** |
> | Tier B (timing/attacker only) | 83.1% | 31.8% | **51.3 points** |
>
> Mechanism confirmed: 98.7% mean attacker-IP overlap between naive train/test splits (near-total memorization, not generalization). Robustness check: excluding the single most dominant attacker (14% of all data) only reduces naive accuracy by 2.8 points (83.1% → 80.3%) — confirming the overstatement is systemic across many repeat attackers, not a fragile artifact of one outlier. Core empirical work for the paper is complete; proceeding to Phase 5 (writing).

---

## Phase 0: Foundation  
**Goal:** Lock the scope so nothing shifts mid-project.

- [ ] Write a 1-page research proposal: research question, hypothesis, novelty claim, success metrics — get your supervisor's (Irfan Alam's) sign-off before building anything
- [ ] Finalize related-work list (already identified):
  - Harrison, Rutherford, White (2015, HICSS) — "The Honey Community" — your foundational anchor
  - Springer (2017) — "Honeypots and honeynets: issues of privacy" — qualitative problem statement you're quantifying
  - Differential privacy in cybersecurity analytics (threat intel anonymization inadequacy)
  - Adjacent-domain re-identification/linkage attack papers (ECG data, mobility data) — methodology template
  - AnonTokens (decoy record tracing) — adjacent technique reference
  - MISP/STIX threat-intel sharing standards — for realistic data format
  - Feito-Casares, Gómez-Talal, Rojo-Álvarez (2026, arXiv) — MURHCAD dataset paper itself, cite as your data source
  - Valeros & García — Hornet 40 (2022) and CTU Hornet 65 Niner (2025) — cite as related multi-site honeypot datasets, and evaluate as a possible second real data source (see Phase 1)
- [ ] **Confirm dataset access** — locate and download the MURHCAD dataset repository (referenced in Feito-Casares et al. 2025/2026; check arXiv 2601.05813 for the linked repository, likely GitHub or Zenodo) before committing to the full plan below
- [ ] Set up project structure: git repo, directory layout (`/data`, `/src`, `/results`, `/figures`, `/paper`)
- [ ] Reuse environment from prior GAN+RL project (Python, scikit-learn, PyTorch, pandas) — confirm versions still work
- [ ] Define success metrics explicitly, in writing, before running anything:
  - Primary: re-identification accuracy (top-1, top-k) vs. random-guess baseline (1/N orgs)
  - Secondary: per-org precision/recall, confusion matrix patterns
  - Tertiary: utility-privacy tradeoff curve (Phase 4)

**Deliverable:** Signed-off 1-pager + repo skeleton + locked metric definitions

---

## Phase 1: Real Multi-Site Honeypot Data Acquisition  
**Goal:** Acquire real, ground-truth-labeled honeypot data from genuinely distinct deployment sites — no simulation, no synthetic fingerprints.

### The core dataset: MURHCAD (Multi-Regional Cloud Honeynet Dataset)
A real, recent (June 2025 collection, 2026 publication), publicly available dataset that fits this study almost exactly:
- <cite index="379-1">132,425 individual attack events captured by three honeypots (Cowrie, Dionaea, and SentryPeer) deployed across four geographically dispersed virtual machines on Microsoft Azure, collected over a continuous 72-hour window.</cite>
- <cite index="379-1">Each event record includes enriched metadata: UTC timestamps, source/destination IPs, autonomous system and organizational mappings, geolocation coordinates, targeted ports, and honeypot identifiers.</cite>
- Critically, the dataset already contains a **real ground-truth label** for exactly what you need: `dstHostname` (which VM/region — vm-centralindia, vm-centralus, vm-spaincentral, vm-southafricanorth — captured each event). This is your `site_id`, and it's genuinely real, not something you invent.
- <cite index="379-2">Records and storage are organized as raw JSON batches plus a preprocessed, cleaned CSV, with a full data-preprocessing notebook, README, and requirements.txt provided, released under MIT License to facilitate academic and commercial reuse.</cite>

### Honest framing note:
These four regions are one research group's deployment across four locations — not four independent real-world companies. That's still genuinely real data (real attackers, real infrastructure, real geographic/network diversity), and it's a legitimate stand-in for "distinct deployment sites in a threat-sharing community," which is exactly what CIAS's Honey-Community model coordinates. Just don't overstate it in your paper as "four different organizations" — frame it accurately as "four geographically distinct honeypot deployment sites," which is both true and still supports the privacy-leakage question.

### Technical steps:
1. **Locate and download the dataset** — find the linked repository from the MURHCAD paper (arXiv 2601.05813) or its companion tutorial paper by the same authors; confirm the raw JSON batches and preprocessed CSV are accessible
2. **Load and inspect:** confirm the schema matches what's documented (weekday, date, srcIp, srcOrg, srcCountryName, dstIp, dstIpInternal, dstHostname, dstCountryName, protocol, attackType, hour, day, srcPort, srcLat/srcLon, dstPort, dstLat/dstLon)
3. **Set your target label:** `dstHostname` (or `dstIpInternal`) becomes your ground-truth "site/org" label for the re-identification task in Phase 3
4. **(Optional, strengthens the paper) Add a second independent real source:** evaluate whether Hornet 40 or CTU Hornet 65 Niner (Valeros & García — geographically distributed low-interaction honeypot datasets, standardized Zeek/Argus logs) are accessible for download. If so, treating MURHCAD's 4 sites and a second dataset's sites as separate "communities" lets you test whether re-identification generalizes across genuinely independent deployments, not just within one research group's infrastructure — a stronger claim than using MURHCAD alone.

**Deliverable:** Confirmed, downloaded, inspected real dataset(s) with real ground-truth site/deployment labels

**Tools:** Python, pandas, requests/wget for dataset download, Jupyter (the dataset ships with its own preprocessing notebook — start from that rather than writing one from scratch)

---

## Phase 2: Anonymization / Threat-Intelligence Sharing Layer 
**Goal:** Build the "safe to share" version of the data — the version a real CIAS-style community would actually exchange.

### Technical steps:
1. **Define the shared schema**, loosely modeled on MISP/STIX-style threat-intel objects, using MURHCAD's actual fields:
   - **Stripped (direct identifiers):** `dstHostname`, `dstIpInternal`, `dstIp`, `dstGeoIp`, `dstLat`/`dstLon`, `dstCountryName` — anything that directly names or locates the honeypot site
   - **Kept (the "safe to share" behavioral/threat data):** `protocol`, `attackType`, `hour`, `day`, `weekday`, `srcPort`, `srcCountryName` (attacker-side info is the actual point of threat sharing) — plus any derived timing/frequency features you engineer
2. **Build the anonymization pipeline** (Python script):
   - Input: real per-site records from Phase 1, filtered/grouped by `dstHostname`
   - Output: anonymized "shared" dataset with all direct site-identifying fields removed, structurally identical across sites (no visible site label)
3. **Sanity check:** manually inspect a sample to confirm no obvious direct identifiers leak through (this is your anonymization "baseline" — the version everyone assumes is safe)

**Deliverable:** Anonymized shared dataset (this is literally the artifact your Phase 3 attack will try to break)

**Tools:** Python, pandas, regex-based field stripping

---

## Phase 3: Re-Identification / Leakage Attack — Core Contribution 

**Goal:** Prove (or disprove) that residual signal in the "anonymized" data still identifies the source deployment site (`dstHostname`). This is the heart of the paper's novelty, and every number here comes from the real MURHCAD data, not a simulation.

### Technical steps:
1. **Feature engineering** — extract residual fingerprint-like signals from anonymized data that were *not* explicitly stripped:
   - Timing distributions (inter-command delays, session duration patterns)
   - Command sequence patterns (n-gram or sequence-based features)
   - Session structure statistics (depth, branching patterns)
   - Protocol-level quirks (response ordering, subtle latency signatures)

2. **Train the re-identification classifier:**
   - Primary model: Random Forest (reuse your proven baseline approach from the prior paper — you already know this pipeline well)
   - Secondary model: Gradient Boosting or a small neural net, to test whether the leakage finding holds across model types (robustness check — reviewers will ask this)
   - Train/test split: stratified k-fold cross-validation across sessions (k=5), never leaking test-org sessions into training

3. **Evaluate:**
   - Top-1 and top-k re-identification accuracy vs. random-guess baseline (1/N)
   - Per-org precision/recall — which orgs are easiest/hardest to re-identify, and why (ties back to your fingerprint design choices)
   - Confusion matrix — which orgs get confused with which (interesting secondary finding if two orgs with similar configs get conflated)
   - Bootstrap confidence intervals on accuracy — you need statistical backing that the leakage is real, not noise

**Deliverable:** Trained re-identification model(s), full evaluation table/confusion matrix, statistical significance results

**Tools:** scikit-learn (RandomForestClassifier, GradientBoostingClassifier), PyTorch (if using a neural net), scipy for bootstrap CIs

**This phase is your headline result.** If re-identification accuracy is meaningfully above random baseline, you have your core finding.

---

## Phase 4: Naive-vs-Grouped Evaluation Gap — Quantifying Overstatement  

**Goal:** REFRAMED per Phase 3's finding. Instead of testing whether privacy mitigations reduce an already-thin leakage signal, quantify exactly how much a naive (non-attacker-grouped) evaluation overstates re-identification risk compared to the rigorous GroupKFold evaluation — this is now the paper's core empirical contribution.

### Technical steps:
1. **Run the identical Tier A / Tier B classifiers with plain random K-fold** (no grouping by srcIp) — this is the "naive" evaluation a less careful study would report
2. **Directly compare naive vs. grouped accuracy, side by side, same features, same model, same folds count:**
   - Naive random K-fold accuracy (expected: inflated, likely well above majority baseline)
   - GroupKFold-by-attacker accuracy (already have: 36.3% / 31.8%, both ≤ majority baseline)
   - The gap between these two numbers **is** the headline figure of the paper
3. **Explain the mechanism quantitatively:** show how many attacker IPs appear in both train and test under naive random K-fold (this should be substantial, given the high-volume repeat attackers), and demonstrate that removing/holding out those repeat attackers is precisely what collapses the naive number down to the grouped number
4. **(Optional, strengthens the paper further):** repeat the naive-vs-grouped comparison after excluding the single most dominant attacker IP entirely, to show how much of the naive "signal" rides on just one or two extreme outliers

**Deliverable:** A clean quantitative table/figure showing naive-vs-grouped accuracy gap, plus the mechanism (repeat-attacker overlap) explaining it

**Tools:** Same as Phase 3 — reuse the existing pipeline, just swap GroupKFold for plain KFold as a second evaluation condition

---

## Phase 5: Writing  

**Goal:** Convert results into a submission-ready manuscript. Start this in parallel with Phase 3–4, don't wait until results are done.

### Order of writing (start early where possible):
1. **Related Work** — can be drafted now, using your existing lit review (3-part structure: CIAS anchor → 2017 qualitative problem → your quantitative contribution)
2. **Introduction** — can be largely drafted once Phase 0 scope is locked
3. **Threat Model** — define adversary assumptions (what does the "attacker" trying to re-identify an org know/have access to?) — draft during Phase 2–3
4. **Methodology** — write as you complete each phase, while implementation details are fresh
5. **Experimental Setup** — dataset stats, model configs, evaluation protocol
6. **Results** — build figures/tables as they come out of Phase 3–4, don't batch this at the end
7. **Discussion/Limitations** — be explicit and honest about scope: this uses one research group's real multi-region deployment (MURHCAD), which is genuine real-world data but not literally independent companies; a 72-hour collection window; and generalizability to a true multi-organization CIAS-style community remains to be validated with data from genuinely separate institutions
8. **Conclusion**
9. **Abstract** — write last, once findings are final

### Quality control (non-negotiable, given prior experience):
- [ ] Full reference audit — verify every citation actually exists and says what you claim (same process as the 28→30 citation audit on your prior paper)
- [ ] No fabricated or reporting-theater results — every number in the paper must trace back to an actual run you can reproduce
- [ ] Internal honesty check: does the Limitations section actually acknowledge the real constraints (simulated orgs, not real multi-institution deployment)?
- [ ] Supervisor review pass with Irfan Alam before submission

**Deliverable:** Submission-ready manuscript

---

## Phase 6: Submission  
- [ ] Submit manuscript to target journal

 
