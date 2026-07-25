"""Generate research charts from the canonical benchmark metrics artifact."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render charts from generated Trust Gate benchmark metrics."
    )
    parser.add_argument(
        "--metrics",
        default="benchmarks/reports/flask-vulnerable-v1.metrics.json",
    )
    parser.add_argument(
        "--output-dir",
        default="benchmarks/reports/charts",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    metrics_path = Path(args.metrics)
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    tools = sorted(metrics["tools"])
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    colours = ["#2E86AB", "#A23B72", "#3BB273", "#F59E0B"]

    x = np.arange(len(tools))
    width = 0.25
    figure, axis = plt.subplots(figsize=(10, 6))
    for offset, key, label, colour in (
        (-width, "precision", "Precision", "#2E86AB"),
        (0, "recall", "Recall", "#A23B72"),
        (width, "f1", "F1", "#3BB273"),
    ):
        values = [metrics["tools"][tool][key] for tool in tools]
        bars = axis.bar(x + offset, values, width, label=label, color=colour)
        axis.bar_label(bars, fmt="%.3f", padding=3)
    axis.set_xticks(x, tools)
    axis.set_ylim(0, 1.15)
    axis.set_ylabel("Score")
    axis.set_title("Precision, recall, and F1 by scanner")
    axis.legend()
    figure.tight_layout()
    figure.savefig(output / "precision-recall-f1.png", dpi=150)
    plt.close(figure)

    figure, axes = plt.subplots(1, len(tools), figsize=(5 * len(tools), 4))
    axes = np.atleast_1d(axes)
    for axis, tool in zip(axes, tools, strict=True):
        result = metrics["tools"][tool]
        matrix = np.array(
            [
                [result["true_positives"], result["false_positives"]],
                [result["false_negatives"], 0],
            ]
        )
        axis.imshow(matrix, cmap="Blues")
        for row in range(2):
            for column in range(2):
                axis.text(
                    column,
                    row,
                    str(matrix[row, column]),
                    ha="center",
                    va="center",
                )
        axis.set_xticks([0, 1], ["TP", "FP"])
        axis.set_yticks([0, 1], ["Detected", "Missed"])
        axis.set_title(tool)
    figure.tight_layout()
    figure.savefig(output / "confusion-counts.png", dpi=150)
    plt.close(figure)

    ground_truth_ids = sorted(
        {
            identifier
            for tool in tools
            for identifier in (
                metrics["tools"][tool]["matched_ground_truth_ids"]
                + metrics["tools"][tool]["missed_ground_truth_ids"]
            )
        }
    )
    figure, axis = plt.subplots(figsize=(12, 5))
    width = 0.8 / max(len(tools), 1)
    x = np.arange(len(ground_truth_ids))
    for index, tool in enumerate(tools):
        detected = set(metrics["tools"][tool]["matched_ground_truth_ids"])
        values = [1 if identifier in detected else 0 for identifier in ground_truth_ids]
        axis.bar(
            x + (index - (len(tools) - 1) / 2) * width,
            values,
            width,
            label=tool,
            color=colours[index % len(colours)],
        )
    axis.set_xticks(x, ground_truth_ids)
    axis.set_yticks([0, 1], ["Missed", "Detected"])
    axis.set_title("Ground-truth detection by scanner")
    axis.legend()
    figure.tight_layout()
    figure.savefig(output / "ground-truth-detection.png", dpi=150)
    plt.close(figure)

    figure, axis = plt.subplots(figsize=(7, 5))
    false_positives = [
        metrics["tools"][tool]["false_positives"] for tool in tools
    ]
    bars = axis.bar(tools, false_positives, color=colours[: len(tools)])
    axis.bar_label(bars, padding=3)
    axis.set_ylabel("False-positive findings")
    axis.set_title("False-positive findings by scanner")
    figure.tight_layout()
    figure.savefig(output / "false-positives.png", dpi=150)
    plt.close(figure)

    print(f"Generated 4 charts from {metrics_path} in {output}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
