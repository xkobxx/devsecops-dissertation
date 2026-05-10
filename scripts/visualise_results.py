import json
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

os.makedirs('reports/charts', exist_ok=True)

# ── Data ──────────────────────────────────────────────────────────────
tools    = ['Bandit', 'Semgrep', 'Combined']
precision = [0.571, 0.625, 0.750]
recall    = [0.800, 1.000, 1.000]
f1        = [0.666, 0.769, 0.857]
fp_counts = [3,     3,     4    ]

colours = ['#2E86AB', '#A23B72', '#3BB273']

# ── Chart 1: Precision, Recall, F1 grouped bar chart ─────────────────
fig, ax = plt.subplots(figsize=(10, 6))
x   = np.arange(len(tools))
w   = 0.25

bars_p = ax.bar(x - w,   precision, w, label='Precision', color='#2E86AB', edgecolor='white')
bars_r = ax.bar(x,       recall,    w, label='Recall',    color='#A23B72', edgecolor='white')
bars_f = ax.bar(x + w,   f1,        w, label='F1 Score',  color='#3BB273', edgecolor='white')

for bars in [bars_p, bars_r, bars_f]:
    for bar in bars:
        h = bar.get_height()
        ax.annotate(f'{h:.3f}',
                    xy=(bar.get_x() + bar.get_width() / 2, h),
                    xytext=(0, 4), textcoords='offset points',
                    ha='center', va='bottom', fontsize=9)

ax.set_xlabel('Tool', fontsize=12)
ax.set_ylabel('Score', fontsize=12)
ax.set_title('Figure 1: Precision, Recall, and F1 Score by Tool', fontsize=13, fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(tools, fontsize=11)
ax.set_ylim(0, 1.15)
ax.legend(fontsize=10)
ax.yaxis.grid(True, linestyle='--', alpha=0.6)
ax.set_axisbelow(True)
plt.tight_layout()
plt.savefig('reports/charts/chart1_precision_recall_f1.png', dpi=150)
plt.close()
print("Chart 1 saved.")

# ── Chart 2: Confusion matrix values (TP / FP / FN) ──────────────────
tp = [4, 5, 6]
fp = [3, 3, 4]
fn = [1, 0, 0]

fig, axes = plt.subplots(1, 3, figsize=(12, 5))
tool_labels = ['Bandit', 'Semgrep', 'Combined']
data_sets   = zip(tool_labels, tp, fp, fn, colours)

for ax, (tool, t, f_p, f_n, col) in zip(axes, data_sets):
    matrix = np.array([[t, f_p], [f_n, 0]])
    labels = [['TP', 'FP'], ['FN', 'TN*']]
    im = ax.imshow(matrix, cmap='Blues', vmin=0, vmax=6)
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f'{labels[i][j]}\n{matrix[i, j]}',
                    ha='center', va='center', fontsize=14, fontweight='bold',
                    color='white' if matrix[i, j] > 3 else 'black')
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(['Predicted\nPositive', 'Predicted\nNegative'], fontsize=9)
    ax.set_yticklabels(['Actual\nPositive', 'Actual\nNegative'], fontsize=9)
    ax.set_title(f'{tool}', fontsize=12, fontweight='bold')

fig.suptitle('Figure 2: Confusion Matrices by Tool (TN* not applicable for SAST)',
             fontsize=11, fontweight='bold', y=1.02)
plt.tight_layout()
plt.savefig('reports/charts/chart2_confusion_matrices.png', dpi=150, bbox_inches='tight')
plt.close()
print("Chart 2 saved.")

# ── Chart 3: Detection rate per vulnerability ─────────────────────────
vuln_ids = ['VULN-001\nHardcoded\nCreds', 'VULN-002\nSQL\nInjection',
            'VULN-003\nCmd\nInjection', 'VULN-004\nCode\nInjection',
            'VULN-005\nUnvalidated\nRedirect', 'VULN-006\nPath\nTraversal']

bandit_det  = [1, 1, 1, 1, 0, 0]
semgrep_det = [0, 1, 1, 1, 1, 1]
combined    = [1, 1, 1, 1, 1, 1]

x   = np.arange(len(vuln_ids))
w   = 0.25
fig, ax = plt.subplots(figsize=(13, 6))

ax.bar(x - w,  bandit_det,  w, label='Bandit',   color='#2E86AB', edgecolor='white')
ax.bar(x,      semgrep_det, w, label='Semgrep',  color='#A23B72', edgecolor='white')
ax.bar(x + w,  combined,    w, label='Combined', color='#3BB273', edgecolor='white')

ax.set_xlabel('Vulnerability', fontsize=11)
ax.set_ylabel('Detected (1 = Yes, 0 = No)', fontsize=11)
ax.set_title('Figure 3: Per-Vulnerability Detection by Tool', fontsize=13, fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(vuln_ids, fontsize=8)
ax.set_ylim(0, 1.3)
ax.set_yticks([0, 1])
ax.legend(fontsize=10)
ax.yaxis.grid(True, linestyle='--', alpha=0.5)
ax.set_axisbelow(True)
plt.tight_layout()
plt.savefig('reports/charts/chart3_per_vuln_detection.png', dpi=150)
plt.close()
print("Chart 3 saved.")

# ── Chart 4: False positive count per tool ────────────────────────────
fig, ax = plt.subplots(figsize=(7, 5))
bars = ax.bar(tools, fp_counts, color=colours, edgecolor='white', width=0.4)
for bar in bars:
    h = bar.get_height()
    ax.text(bar.get_x() + bar.get_width() / 2, h + 0.05, str(int(h)),
            ha='center', va='bottom', fontsize=12, fontweight='bold')
ax.set_xlabel('Tool', fontsize=12)
ax.set_ylabel('False Positive Count', fontsize=12)
ax.set_title('Figure 4: False Positive Count by Tool', fontsize=13, fontweight='bold')
ax.set_ylim(0, 6)
ax.yaxis.grid(True, linestyle='--', alpha=0.6)
ax.set_axisbelow(True)
plt.tight_layout()
plt.savefig('reports/charts/chart4_false_positives.png', dpi=150)
plt.close()
print("Chart 4 saved.")

print("\nAll charts saved to reports/charts/")
print("Files: chart1_precision_recall_f1.png, chart2_confusion_matrices.png,")
print("       chart3_per_vuln_detection.png, chart4_false_positives.png")