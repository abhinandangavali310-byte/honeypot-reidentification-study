"""
Phase 2: Anonymization / Threat-Intelligence Sharing Layer
============================================================
Produces two "shared" versions of the real MURHCAD dataset, simulating
what a CIAS-style Honey-Community would actually exchange between members.

Tier A (naive anonymization): strips only direct site identifiers
    (hostname, internal/external IP, geolocation). Keeps protocol/port/
    service-level info intact -- this is the "easy" fingerprint signal.

Tier B (aggressive anonymization): additionally strips protocol/port/
    attackType. Forces any re-identification to rely purely on timing
    and attacker-population signal, not on "which service was exposed."

The ground-truth label (dstHostname) is retained in a SEPARATE column
in both outputs for our own evaluation only -- in a real deployment,
this label would never be shared; it exists here so Phase 3 can measure
whether it's recoverable from the rest of the row.
"""

import pandas as pd

RAW_PATH = "../data/raw/HoneyNetEvents_Clean.csv"
OUT_DIR = "../data/processed"

LABEL_COL = "dstHostname"

# Fields that directly or trivially reveal the site -- these NEVER appear
# in either "shared" tier, under any circumstance.
DIRECT_SITE_IDENTIFIERS = [
    "dstIp", "dstIpInternal", "dstGeoIp", "dstLat", "dstLon", "dstCountryName",
]

TIER_A_FEATURES = [
    "hour", "day", "weekday",
    "srcPort", "srcOrg", "srcCountryName", "srcLat", "srcLon",
    "dstPort", "protocol", "attackType",
]

TIER_B_FEATURES = [
    "hour", "day", "weekday",
    "srcPort", "srcOrg", "srcCountryName", "srcLat", "srcLon",
]


def load_raw(path: str = RAW_PATH) -> pd.DataFrame:
    df = pd.read_csv(path, parse_dates=["timestamp"])
    return df


def build_tier(df: pd.DataFrame, feature_cols: list[str]) -> pd.DataFrame:
    out = df[feature_cols].copy()
    out[LABEL_COL] = df[LABEL_COL].values  # kept for evaluation only, never "shared"
    return out


def sanity_check_no_leakage(tier_df: pd.DataFrame, tier_name: str) -> None:
    """Confirm no direct site identifier snuck into a supposedly anonymized tier."""
    leaked = [c for c in DIRECT_SITE_IDENTIFIERS if c in tier_df.columns]
    if leaked:
        raise ValueError(f"{tier_name}: direct identifiers leaked into output: {leaked}")
    print(f"[OK] {tier_name}: no direct site identifiers present. "
          f"Columns: {[c for c in tier_df.columns if c != LABEL_COL]}")


def main():
    df = load_raw()
    print(f"Loaded raw dataset: {df.shape[0]:,} rows, {df.shape[1]} columns\n")

    tier_a = build_tier(df, TIER_A_FEATURES)
    tier_b = build_tier(df, TIER_B_FEATURES)

    sanity_check_no_leakage(tier_a, "Tier A (naive anonymization)")
    sanity_check_no_leakage(tier_b, "Tier B (aggressive anonymization)")

    a_path = f"{OUT_DIR}/tier_a_naive_anon.csv"
    b_path = f"{OUT_DIR}/tier_b_aggressive_anon.csv"
    tier_a.to_csv(a_path, index=False)
    tier_b.to_csv(b_path, index=False)

    print(f"\nSaved Tier A -> {a_path}  ({tier_a.shape[0]:,} rows, {tier_a.shape[1]} cols)")
    print(f"Saved Tier B -> {b_path}  ({tier_b.shape[0]:,} rows, {tier_b.shape[1]} cols)")

    print("\n=== Tier A preview ===")
    print(tier_a.head(3).to_string())
    print("\n=== Tier B preview ===")
    print(tier_b.head(3).to_string())


if __name__ == "__main__":
    main()
