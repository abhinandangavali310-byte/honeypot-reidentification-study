# Naive Evaluation Overstates Re-identification Risk in Shared Honeypot Threat Intelligence

Research code and manuscript for an empirical study of privacy risk in community-scale honeypot threat-intelligence sharing, using real multi-site attack data.

**Core finding:** naive (non-attacker-aware) cross-validation suggests strong re-identification of the source honeypot deployment from anonymized shared data (83% accuracy). Properly accounting for attacker-level data leakage (GroupKFold by attacker IP) shows this is substantially overstated — the naive-to-grouped gap is 30-51 percentage points across two model families (Random Forest, Gradient Boosting) and two anonymization schemes. Full details in [`paper/manuscript_full_draft.md`](paper/manuscript_full_draft.md).

## Repository Structure

```
├── data/
│   ├── raw/                    # Original MURHCAD dataset (see Data Source below)
│   └── processed/              # Tier A / Tier B anonymized datasets (output of phase2)
├── src/
│   ├── phase2_anonymize.py           # Builds the two anonymization tiers
│   ├── phase3_reidentification.py    # Core Random Forest naive-vs-grouped evaluation
│   ├── phase3_diagnostics.py         # Robustness checks (class balance, concentration, etc.)
│   ├── phase4_gradient_boosting.py   # Cross-model robustness check
│   └── generate_figures.py           # Regenerates all 4 manuscript figures
├── figures/                    # The 4 figures used in the paper
├── paper/
│   ├── manuscript_full_draft.md      # Full manuscript draft
│   └── research_roadmap.md           # Full project roadmap/process log
└── requirements.txt
```

## Data Source

This project uses the **MURHCAD dataset** (Multi-Regional Cloud Honeynet Dataset), a real, publicly available dataset released under MIT License:

> Feito Casares, E., Gómez-Talal, I., & Rojo-Álvarez, J.L. (2025). Multi-regional Honeynet Dataset: A Distributed T-Pot Honeypot Deployment Across Azure Regions for Cyber Threat Analysis. arXiv:2601.05813. Dataset DOI: [10.5281/zenodo.15716735](https://doi.org/10.5281/zenodo.15716735).

The processed/cleaned CSV (`HoneyNetEvents_Clean.csv`, ~30MB) is included in `data/raw/` for reproducibility. If you're forking this repo and want the original raw JSON batches, see the Zenodo record above.

## Reproducing the Pipeline

```bash
pip install -r requirements.txt
cd src

# 1. Build the two anonymization tiers from raw data
python phase2_anonymize.py

# 2. Core Random Forest naive-vs-grouped evaluation (both tiers)
python phase3_reidentification.py

# 3. Robustness/diagnostic checks (class balance, fold concentration, dominant-attacker exclusion)
python phase3_diagnostics.py

# 4. Cross-model check with Gradient Boosting
python phase4_gradient_boosting.py

# 5. Regenerate all figures
python generate_figures.py
```

## Key Results

| Evaluation | RF Tier A | RF Tier B | GBoost Tier A | GBoost Tier B | Majority baseline |
|---|---|---|---|---|---|
| Naive K-fold | 83.1% | 83.1% | 79.2% | 78.3% | 40.1% |
| GroupKFold (by attacker) | 36.3% | 31.8% | 49.0% | 34.6% | 40.1% |
| Overstatement | 46.8 pts | 51.3 pts | 30.2 pts | 43.7 pts | — |

See `paper/manuscript_full_draft.md` Section 4 for full discussion, including the diagnostic mechanism (attacker memorization: 99.5% training accuracy vs. 37.1% held-out accuracy for Random Forest) and the cross-model divergence on Tier A specifically.

## Status / Honest Limitations

This is a manuscript draft, not a published or peer-reviewed paper. See Section 5.2 of the manuscript for full disclosed limitations, including: single research-group deployment (not independent organizations), 72-hour collection window, only two model families tested (no hyperparameter tuning, no third architecture), and reliance on a single dataset family. These are documented as genuine open items, not oversights.

## License

Code in this repository: choose a license appropriate for your use (e.g., MIT) before making this repository public — this was not decided during drafting.

Dataset: MIT License (per original MURHCAD release).
