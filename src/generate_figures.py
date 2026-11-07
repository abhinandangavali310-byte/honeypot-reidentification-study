"""
Figure Generation: All Four Manuscript Figures
=================================================
Regenerates fig1-fig4 exactly as they appear in paper/manuscript_full_draft.md.
Uses the final, canonical numbers (Random Forest at n_estimators=200) -- see
paper/manuscript_full_draft.md Section 4 for the numbers these visualize.

Run from src/ after phase3_reidentification.py and phase4_gradient_boosting.py
have been run (or just use the hardcoded canonical values below, which is
what this script does -- no live computation required to regenerate figures).
"""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

FIGURES_DIR = "../figures"
plt.rcParams["font.size"] = 11
plt.rcParams["font.family"] = "DejaVu Sans"


def fig1_confusion_matrix():
    """Tier A, GroupKFold, Random Forest (n_estimators=200) -- the canonical run."""
    short_labels = ["India", "US", "S. Africa", "Spain"]
    cm = np.array([
        [11654, 3926, 19238, 18245],
        [6632, 23533, 3611, 9449],
        [3073, 1954, 7401, 2525],
        [8994, 2488, 4225, 5477],
    ])
    cm_norm = cm / cm.sum(axis=1, keepdims=True) * 100

    fig, ax = plt.subplots(figsize=(6.5, 5.5))
    im = ax.imshow(cm_norm, cmap="Blues", vmin=0, vmax=60)
    for i in range(4):
        for j in range(4):
            val = cm_norm[i, j]
            color = "white" if val > 35 else "black"
            weight = "bold" if i == j else "normal"
            ax.text(j, i, f"{val:.1f}%", ha="center", va="center", color=color,
                     fontsize=11, fontweight=weight)
    ax.set_xticks(range(4)); ax.set_xticklabels(short_labels)
    ax.set_yticks(range(4)); ax.set_yticklabels(short_labels)
    ax.set_xlabel("Predicted Site")
    ax.set_ylabel("True Site")
    ax.set_title("Tier A Re-identification: Confusion Matrix\n"
                  "(GroupKFold by attacker, row-normalized %, n_estimators=200)", fontsize=12)
    cbar = plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cbar.set_label("% of true-class events")
    plt.tight_layout()
    plt.savefig(f"{FIGURES_DIR}/fig1_confusion_matrix.png", dpi=300, bbox_inches="tight")
    plt.close()
    print("fig1_confusion_matrix.png saved")


def fig2_concentration_vs_accuracy():
    """Fold accuracy vs. single-attacker concentration, Tier A GroupKFold."""
    concentration = [0.701, 0.606, 0.537, 0.417, 0.374]
    fold_acc = [0.1429, 0.4634, 0.2807, 0.4629, 0.4650]
    fold_labels = ["Fold 1", "Fold 2", "Fold 3", "Fold 4", "Fold 5"]

    fig, ax = plt.subplots(figsize=(6.5, 5))
    ax.scatter(concentration, fold_acc, s=140, color="#2c5f8a", zorder=3,
               edgecolor="white", linewidth=1.5)
    for i, lbl in enumerate(fold_labels):
        ax.annotate(lbl, (concentration[i], fold_acc[i]), textcoords="offset points",
                     xytext=(10, 5), fontsize=9)
    z = np.polyfit(concentration, fold_acc, 1)
    xline = np.linspace(0.35, 0.72, 50)
    ax.plot(xline, z[0] * xline + z[1], "--", color="gray", alpha=0.7,
             label="Linear trend", zorder=2)
    ax.axhline(0.4007, color="#c0392b", linestyle=":", linewidth=1.5,
                label="Majority-class baseline (40.1%)", zorder=1)
    ax.set_xlabel("Top single attacker's share of fold", fontsize=11)
    ax.set_ylabel("Fold test accuracy", fontsize=11)
    ax.set_title("Fold Accuracy Collapses as Single-Attacker\n"
                  "Concentration Increases (Tier A, GroupKFold)", fontsize=12)
    ax.legend(fontsize=9, loc="upper right")
    ax.set_ylim(0, 0.55)
    ax.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(f"{FIGURES_DIR}/fig2_concentration_vs_accuracy.png", dpi=300, bbox_inches="tight")
    plt.close()
    print("fig2_concentration_vs_accuracy.png saved")


def fig3_naive_vs_grouped():
    """Naive vs. grouped accuracy, Random Forest, both tiers."""
    tiers = ["Tier A\n(protocol/port retained)", "Tier B\n(timing/attacker only)"]
    naive_vals = [0.8312, 0.8308]
    grouped_vals = [0.3630, 0.3182]
    majority = 0.4007

    x = np.arange(len(tiers))
    width = 0.32

    fig, ax = plt.subplots(figsize=(7, 5.5))
    bars1 = ax.bar(x - width / 2, naive_vals, width, label="Naive K-fold (attacker overlap)",
                    color="#c0392b", alpha=0.85)
    bars2 = ax.bar(x + width / 2, grouped_vals, width,
                    label="GroupKFold (by attacker, generalizes to new attackers)",
                    color="#2c5f8a", alpha=0.85)
    ax.axhline(majority, color="black", linestyle=":", linewidth=1.5,
                label=f"Majority-class baseline ({majority * 100:.1f}%)")

    for bars in (bars1, bars2):
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, h + 0.015, f"{h * 100:.1f}%",
                     ha="center", fontsize=10, fontweight="bold")

    ax.set_ylabel("Re-identification accuracy")
    ax.set_title("Naive Evaluation Overstates Re-identification Risk\n"
                  "by 47-51 Percentage Points", fontsize=12)
    ax.set_xticks(x); ax.set_xticklabels(tiers)
    ax.set_ylim(0, 1.0)
    ax.legend(fontsize=9, loc="upper center")
    ax.grid(alpha=0.25, axis="y")
    plt.tight_layout()
    plt.savefig(f"{FIGURES_DIR}/fig3_naive_vs_grouped.png", dpi=300, bbox_inches="tight")
    plt.close()
    print("fig3_naive_vs_grouped.png saved")


def fig4_model_comparison():
    """Naive vs. grouped accuracy, Random Forest vs. Gradient Boosting, Tier A."""
    models = ["Random Forest", "Gradient Boosting"]
    naive_vals = [0.8312, 0.7920]
    grouped_vals = [0.3630, 0.4898]
    majority = 0.4007

    x = np.arange(len(models))
    width = 0.32

    fig, ax = plt.subplots(figsize=(7, 5.5))
    bars1 = ax.bar(x - width / 2, naive_vals, width, label="Naive K-fold",
                    color="#c0392b", alpha=0.85)
    bars2 = ax.bar(x + width / 2, grouped_vals, width, label="GroupKFold (by attacker)",
                    color="#2c5f8a", alpha=0.85)
    ax.axhline(majority, color="black", linestyle=":", linewidth=1.5,
                label=f"Majority-class baseline ({majority * 100:.1f}%)")

    for bars in (bars1, bars2):
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, h + 0.015, f"{h * 100:.1f}%",
                     ha="center", fontsize=10, fontweight="bold")

    ax.set_ylabel("Re-identification accuracy (Tier A)")
    ax.set_title("Naive-vs-Grouped Gap Holds Across Model Families;\n"
                  "Grouped \"Floor\" Is Model-Dependent", fontsize=12)
    ax.set_xticks(x); ax.set_xticklabels(models)
    ax.set_ylim(0, 1.0)
    ax.legend(fontsize=9, loc="upper center")
    ax.grid(alpha=0.25, axis="y")
    plt.tight_layout()
    plt.savefig(f"{FIGURES_DIR}/fig4_model_comparison.png", dpi=300, bbox_inches="tight")
    plt.close()
    print("fig4_model_comparison.png saved")


if __name__ == "__main__":
    fig1_confusion_matrix()
    fig2_concentration_vs_accuracy()
    fig3_naive_vs_grouped()
    fig4_model_comparison()
