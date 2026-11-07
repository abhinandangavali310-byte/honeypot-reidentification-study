"""
Phase 3: Re-Identification / Leakage Attack (Core Contribution)
==================================================================
Trains a Random Forest to predict the source site (dstHostname) from
each anonymization tier, measuring whether "anonymized" shared data
still leaks site identity.

METHODOLOGY NOTE -- read before trusting the numbers:
-------------------------------------------------------
Evaluation uses GroupKFold grouped by srcIp, NOT a plain random K-fold.

Why this matters: srcOrg, srcCountryName, srcLat, and srcLon are all
deterministic functions of srcIp (derived via ASN/geolocation lookup),
and many events from the same attacker arrive in tight time bursts with
near-identical feature values. A plain random split would let rows from
the same attacker leak across train and test, inflating accuracy in a
way that would NOT generalize to a genuinely new, previously-unseen
attacker. Grouping by srcIp forces every row from a given attacker into
either train or test, never both -- this tests the real question the
paper is asking: if a brand-new attacker hits one of these sites, can
we tell which site from behavioral signal alone?

Two baselines are reported, not one:
  - Uniform random  (1 / n_classes)
  - Majority-class  (always predict the plurality site) -- since the
    four sites are imbalanced (India ~40% of events), majority-class is
    the harder, more honest bar to clear.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
    top_k_accuracy_score,
)
from sklearn.model_selection import GroupKFold
from sklearn.preprocessing import LabelEncoder

RAW_PATH = "../data/raw/HoneyNetEvents_Clean.csv"
TIER_A_PATH = "../data/processed/tier_a_naive_anon.csv"
TIER_B_PATH = "../data/processed/tier_b_aggressive_anon.csv"

LABEL_COL = "dstHostname"
N_SPLITS = 5
TOP_N_ORG = 30
TOP_N_COUNTRY = 20
RANDOM_STATE = 42
N_BOOTSTRAP = 1000


def bucket_rare_categories(series: pd.Series, top_n: int) -> pd.Series:
    top_vals = series.value_counts().nlargest(top_n).index
    return series.where(series.isin(top_vals), other="OTHER")


def encode_features(df: pd.DataFrame, categorical_cols: list[str], numeric_cols: list[str]) -> pd.DataFrame:
    df = df.copy()
    if "srcOrg" in categorical_cols:
        df["srcOrg"] = bucket_rare_categories(df["srcOrg"], TOP_N_ORG)
    if "srcCountryName" in categorical_cols:
        df["srcCountryName"] = bucket_rare_categories(df["srcCountryName"], TOP_N_COUNTRY)
    dummies = pd.get_dummies(df[categorical_cols], prefix=categorical_cols)
    X = pd.concat([df[numeric_cols].reset_index(drop=True), dummies.reset_index(drop=True)], axis=1)
    return X


def evaluate_tier(tier_path: str, categorical_cols: list[str], numeric_cols: list[str],
                   tier_name: str, srcip_series: pd.Series) -> dict:
    df = pd.read_csv(tier_path)
    assert len(df) == len(srcip_series), "Row count mismatch between tier file and srcIp series"

    X = encode_features(df, categorical_cols, numeric_cols)
    le = LabelEncoder()
    y = le.fit_transform(df[LABEL_COL].values)
    groups = srcip_series.values

    gkf = GroupKFold(n_splits=N_SPLITS)
    all_preds = np.zeros_like(y)
    all_probs = np.zeros((len(y), len(le.classes_)))

    for fold, (train_idx, test_idx) in enumerate(gkf.split(X, y, groups)):
        clf = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=RANDOM_STATE)
        clf.fit(X.iloc[train_idx], y[train_idx])
        all_preds[test_idx] = clf.predict(X.iloc[test_idx])
        all_probs[test_idx] = clf.predict_proba(X.iloc[test_idx])
        fold_acc = accuracy_score(y[test_idx], all_preds[test_idx])
        print(f"  Fold {fold + 1}/{N_SPLITS} accuracy: {fold_acc:.4f}  (test size: {len(test_idx):,})")

    overall_acc = accuracy_score(y, all_preds)
    top2_acc = top_k_accuracy_score(y, all_probs, k=2)

    rng = np.random.RandomState(RANDOM_STATE)
    n = len(y)
    boot_accs = [accuracy_score(y[idx], all_preds[idx])
                 for idx in (rng.randint(0, n, n) for _ in range(N_BOOTSTRAP))]
    ci_low, ci_high = np.percentile(boot_accs, [2.5, 97.5])

    precision, recall, f1, support = precision_recall_fscore_support(
        y, all_preds, labels=range(len(le.classes_)), zero_division=0
    )

    print(f"\n--- {tier_name} Results ---")
    print(f"Overall accuracy: {overall_acc:.4f}  (95% bootstrap CI: [{ci_low:.4f}, {ci_high:.4f}])")
    print(f"Top-2 accuracy:   {top2_acc:.4f}")
    print("\nPer-class performance:")
    for i, cls in enumerate(le.classes_):
        print(f"  {cls:22s} precision={precision[i]:.3f}  recall={recall[i]:.3f}  "
              f"f1={f1[i]:.3f}  support={support[i]}")

    cm = confusion_matrix(y, all_preds)
    print(f"\nConfusion matrix (rows=true, cols=predicted), class order={list(le.classes_)}:")
    print(cm)

    return {
        "tier_name": tier_name, "accuracy": overall_acc, "ci": (ci_low, ci_high),
        "top2_accuracy": top2_acc, "classes": list(le.classes_),
        "precision": precision, "recall": recall, "f1": f1, "support": support,
        "confusion_matrix": cm, "n_features": X.shape[1],
    }


def main():
    raw = pd.read_csv(RAW_PATH)
    srcip_series = raw["srcIp"]

    class_counts = raw[LABEL_COL].value_counts()
    majority_baseline = class_counts.max() / class_counts.sum()
    uniform_baseline = 1.0 / class_counts.nunique()
    print(f"Baselines -> uniform random: {uniform_baseline:.4f}   "
          f"majority-class: {majority_baseline:.4f}\n")

    print("=" * 65)
    print("TIER A (naive anonymization) -- protocol/port retained")
    print("=" * 65)
    results_a = evaluate_tier(
        TIER_A_PATH,
        categorical_cols=["weekday", "srcOrg", "srcCountryName", "protocol", "attackType"],
        numeric_cols=["hour", "day", "srcPort", "srcLat", "srcLon", "dstPort"],
        tier_name="Tier A", srcip_series=srcip_series,
    )

    print("\n" + "=" * 65)
    print("TIER B (aggressive anonymization) -- timing/attacker only")
    print("=" * 65)
    results_b = evaluate_tier(
        TIER_B_PATH,
        categorical_cols=["weekday", "srcOrg", "srcCountryName"],
        numeric_cols=["hour", "day", "srcPort", "srcLat", "srcLon"],
        tier_name="Tier B", srcip_series=srcip_series,
    )

    print("\n" + "=" * 65)
    print("SUMMARY")
    print("=" * 65)
    print(f"{'Uniform baseline':30s} {uniform_baseline:.4f}")
    print(f"{'Majority-class baseline':30s} {majority_baseline:.4f}")
    print(f"{'Tier A accuracy (n=' + str(results_a['n_features']) + ' feats)':30s} "
          f"{results_a['accuracy']:.4f}  CI [{results_a['ci'][0]:.4f}, {results_a['ci'][1]:.4f}]")
    print(f"{'Tier B accuracy (n=' + str(results_b['n_features']) + ' feats)':30s} "
          f"{results_b['accuracy']:.4f}  CI [{results_b['ci'][0]:.4f}, {results_b['ci'][1]:.4f}]")

    return results_a, results_b


if __name__ == "__main__":
    main()
