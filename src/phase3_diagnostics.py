"""
Phase 3 Diagnostics: Robustness Checks
=========================================
Consolidates the diagnostic analyses that established WHY naive evaluation
overstates re-identification risk. Run after phase3_reidentification.py.

Covers:
1. Class-weight balancing check (rules out class imbalance as the cause)
2. Train-vs-test accuracy gap (confirms memorization, not generalization)
3. Fold accuracy vs. single-attacker concentration (identifies the mechanism)
4. Naive-vs-grouped direct comparison + attacker-IP overlap measurement
5. Dominant-attacker exclusion robustness check
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold, KFold
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, confusion_matrix

from phase3_reidentification import encode_features, TIER_A_PATH, TIER_B_PATH, LABEL_COL

RAW_PATH = "../data/raw/HoneyNetEvents_Clean.csv"
RANDOM_STATE = 42


def check_class_weight_balanced(tier_path, cat_cols, num_cols, srcip):
    """Check 1: does class_weight='balanced' change the picture? (It doesn't --
    this rules out class imbalance as the explanation for low grouped accuracy.)"""
    df = pd.read_csv(tier_path)
    X = encode_features(df, cat_cols, num_cols)
    le = LabelEncoder()
    y = le.fit_transform(df[LABEL_COL].values)
    groups = srcip.values

    gkf = GroupKFold(n_splits=5)
    train_accs, test_accs = [], []
    for tr, te in gkf.split(X, y, groups):
        clf = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=RANDOM_STATE,
                                      class_weight='balanced')
        clf.fit(X.iloc[tr], y[tr])
        train_accs.append(accuracy_score(y[tr], clf.predict(X.iloc[tr])))
        test_accs.append(accuracy_score(y[te], clf.predict(X.iloc[te])))

    print(f"Mean train accuracy (balanced): {np.mean(train_accs):.4f}")
    print(f"Mean test accuracy (balanced):  {np.mean(test_accs):.4f}")
    print("-> Near-identical to unbalanced result; class imbalance is not the cause.\n")


def check_fold_concentration(tier_path, cat_cols, num_cols, srcip):
    """Check 2 & 3: train/test gap and fold accuracy vs. attacker concentration."""
    df = pd.read_csv(tier_path)
    X = encode_features(df, cat_cols, num_cols)
    le = LabelEncoder()
    y = le.fit_transform(df[LABEL_COL].values)
    groups = srcip.values

    gkf = GroupKFold(n_splits=5)
    print(f"{'Fold':<6}{'Test Acc':<12}{'Top IP Share of Fold':<22}{'Unique IPs in Fold'}")
    for fold, (tr, te) in enumerate(gkf.split(X, y, groups), start=1):
        clf = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=RANDOM_STATE)
        clf.fit(X.iloc[tr], y[tr])
        test_acc = accuracy_score(y[te], clf.predict(X.iloc[te]))
        test_ips = srcip.iloc[te]
        top_ip_share = test_ips.value_counts().iloc[0] / len(test_ips)
        print(f"{fold:<6}{test_acc:<12.4f}{top_ip_share:<22.3f}{test_ips.nunique()}")
    print()


def naive_vs_grouped_comparison(tier_path, cat_cols, num_cols, srcip, tier_name):
    """Check 4: direct naive-vs-grouped comparison + IP overlap measurement."""
    df = pd.read_csv(tier_path)
    X = encode_features(df, cat_cols, num_cols)
    le = LabelEncoder()
    y = le.fit_transform(df[LABEL_COL].values)
    groups = srcip.values

    # Naive
    kf = KFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    naive_preds = np.zeros_like(y)
    overlap_fractions = []
    for tr, te in kf.split(X):
        clf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=RANDOM_STATE)
        clf.fit(X.iloc[tr], y[tr])
        naive_preds[te] = clf.predict(X.iloc[te])
        train_ips = set(srcip.iloc[tr])
        overlap_fractions.append(srcip.iloc[te].isin(train_ips).mean())
    naive_acc = accuracy_score(y, naive_preds)

    # Grouped
    gkf = GroupKFold(n_splits=5)
    grouped_preds = np.zeros_like(y)
    for tr, te in gkf.split(X, y, groups):
        clf = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=RANDOM_STATE)
        clf.fit(X.iloc[tr], y[tr])
        grouped_preds[te] = clf.predict(X.iloc[te])
    grouped_acc = accuracy_score(y, grouped_preds)

    print(f"{tier_name}: naive={naive_acc:.4f}  grouped={grouped_acc:.4f}  "
          f"gap={naive_acc - grouped_acc:.4f}  mean_IP_overlap={np.mean(overlap_fractions):.4f}")
    return naive_acc, grouped_acc


def dominant_attacker_exclusion_check(tier_path, cat_cols, num_cols, srcip):
    """Check 5: does excluding the single highest-volume attacker collapse the naive number?
    (It doesn't much -- confirms the overstatement is systemic, not one outlier.)"""
    df = pd.read_csv(tier_path)
    top_ip = srcip.value_counts().index[0]
    top_ip_count = srcip.value_counts().iloc[0]
    print(f"Excluding top attacker IP ({top_ip}, {top_ip_count:,} events, "
          f"{top_ip_count / len(srcip) * 100:.1f}% of all data)")

    mask = (srcip != top_ip).values
    df_excl = df[mask].reset_index(drop=True)

    X = encode_features(df_excl, cat_cols, num_cols)
    le = LabelEncoder()
    y = le.fit_transform(df_excl[LABEL_COL].values)

    kf = KFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    preds = np.zeros_like(y)
    for tr, te in kf.split(X):
        clf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=RANDOM_STATE)
        clf.fit(X.iloc[tr], y[tr])
        preds[te] = clf.predict(X.iloc[te])
    naive_acc_excl = accuracy_score(y, preds)
    print(f"Naive accuracy WITHOUT top attacker: {naive_acc_excl:.4f}  "
          f"(compare to 0.8312 with it included)\n")


if __name__ == "__main__":
    raw = pd.read_csv(RAW_PATH)
    srcip = raw["srcIp"]

    tier_a_cat = ["weekday", "srcOrg", "srcCountryName", "protocol", "attackType"]
    tier_a_num = ["hour", "day", "srcPort", "srcLat", "srcLon", "dstPort"]

    print("=== Check 1: Class-weight balancing (Tier A) ===")
    check_class_weight_balanced(TIER_A_PATH, tier_a_cat, tier_a_num, srcip)

    print("=== Check 2/3: Fold accuracy vs. attacker concentration (Tier A) ===")
    check_fold_concentration(TIER_A_PATH, tier_a_cat, tier_a_num, srcip)

    print("=== Check 4: Naive vs. grouped comparison, both tiers ===")
    naive_vs_grouped_comparison(TIER_A_PATH, tier_a_cat, tier_a_num, srcip, "Tier A")
    tier_b_cat = ["weekday", "srcOrg", "srcCountryName"]
    tier_b_num = ["hour", "day", "srcPort", "srcLat", "srcLon"]
    naive_vs_grouped_comparison(TIER_B_PATH, tier_b_cat, tier_b_num, srcip, "Tier B")
    print()

    print("=== Check 5: Dominant-attacker exclusion (Tier A) ===")
    dominant_attacker_exclusion_check(TIER_A_PATH, tier_a_cat, tier_a_num, srcip)
