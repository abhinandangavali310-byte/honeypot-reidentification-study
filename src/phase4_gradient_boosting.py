"""
Phase 4a: Cross-Model Robustness Check (Gradient Boosting)
=============================================================
Repeats the naive-vs-grouped comparison from phase3_reidentification.py using
Gradient Boosting instead of Random Forest, on both anonymization tiers.

Key finding this produces: the naive/grouped gap holds for both models
(confirming the core methodological claim generalizes across classifiers),
but the two models disagree on whether Tier A's grouped accuracy clears the
majority-class baseline -- Random Forest falls below it, Gradient Boosting
exceeds it. Both models agree Tier B's grouped accuracy falls below baseline.
See Section 4.5 of paper/manuscript_full_draft.md for full discussion.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import GroupKFold, KFold
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score

from phase3_reidentification import encode_features, TIER_A_PATH, TIER_B_PATH, LABEL_COL

RAW_PATH = "../data/raw/HoneyNetEvents_Clean.csv"
RANDOM_STATE = 42
N_ESTIMATORS = 50  # kept modest -- Gradient Boosting is far slower than Random Forest
MAX_DEPTH = 3


def run_gboost_both_protocols(tier_path, cat_cols, num_cols, tier_name, srcip):
    df = pd.read_csv(tier_path)
    X = encode_features(df, cat_cols, num_cols)
    le = LabelEncoder()
    y = le.fit_transform(df[LABEL_COL].values)
    groups = srcip.values

    # Grouped evaluation
    gkf = GroupKFold(n_splits=5)
    grouped_preds = np.zeros_like(y)
    train_accs = []
    for tr, te in gkf.split(X, y, groups):
        clf = GradientBoostingClassifier(n_estimators=N_ESTIMATORS, max_depth=MAX_DEPTH,
                                          random_state=RANDOM_STATE)
        clf.fit(X.iloc[tr], y[tr])
        grouped_preds[te] = clf.predict(X.iloc[te])
        train_accs.append(accuracy_score(y[tr], clf.predict(X.iloc[tr])))
    grouped_acc = accuracy_score(y, grouped_preds)
    mean_train_acc = np.mean(train_accs)

    # Naive evaluation
    kf = KFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    naive_preds = np.zeros_like(y)
    for tr, te in kf.split(X):
        clf = GradientBoostingClassifier(n_estimators=N_ESTIMATORS, max_depth=MAX_DEPTH,
                                          random_state=RANDOM_STATE)
        clf.fit(X.iloc[tr], y[tr])
        naive_preds[te] = clf.predict(X.iloc[te])
    naive_acc = accuracy_score(y, naive_preds)

    print(f"{tier_name} (Gradient Boosting): naive={naive_acc:.4f}  grouped={grouped_acc:.4f}  "
          f"gap={naive_acc - grouped_acc:.4f}  mean_train_acc={mean_train_acc:.4f}")
    return {"tier": tier_name, "naive": naive_acc, "grouped": grouped_acc,
            "gap": naive_acc - grouped_acc, "mean_train_acc": mean_train_acc}


if __name__ == "__main__":
    raw = pd.read_csv(RAW_PATH)
    srcip = raw["srcIp"]

    print("Gradient Boosting robustness check")
    print("Compare to Random Forest headline: Tier A naive=0.8312/grouped=0.3630, "
          "Tier B naive=0.8308/grouped=0.3182\n")

    results_a = run_gboost_both_protocols(
        TIER_A_PATH,
        cat_cols=["weekday", "srcOrg", "srcCountryName", "protocol", "attackType"],
        num_cols=["hour", "day", "srcPort", "srcLat", "srcLon", "dstPort"],
        tier_name="Tier A", srcip=srcip,
    )
    results_b = run_gboost_both_protocols(
        TIER_B_PATH,
        cat_cols=["weekday", "srcOrg", "srcCountryName"],
        num_cols=["hour", "day", "srcPort", "srcLat", "srcLon"],
        tier_name="Tier B", srcip=srcip,
    )

    print("\n=== Summary ===")
    print(f"{'Tier':<10}{'Naive':<10}{'Grouped':<10}{'Gap':<10}")
    for r in (results_a, results_b):
        print(f"{r['tier']:<10}{r['naive']:<10.4f}{r['grouped']:<10.4f}{r['gap']:<10.4f}")
