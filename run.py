"""Launch the network traffic analyzer and expose its Python API."""

import argparse
import csv
from pathlib import Path
import sys

import pandas as pd

from analyze_traffic import analyze, load_flows, make_chart, make_report
from generate_sample_data import generate_sample_csv


def bundled_sample():
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).parent))
    return base / "data" / "sample_traffic.csv"


def generate_demo_csv(output_path="data/sample_traffic.csv", seed=42):
    """Create a reproducible sample dataset and return its Path."""
    return generate_sample_csv(output_path, seed=seed)


def save_events(results, path):
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["event", "window", "subject", "metric", "value"])
        for when, size in results["spikes"].items():
            writer.writerow(["volume_spike", when, "all traffic", "bytes", int(size)])
        for when, size in results["drops"].items():
            writer.writerow(["traffic_drop", when, "all traffic", "bytes", int(size)])
        for (when, source), count in results["sweeps"].items():
            writer.writerow(["port_sweep", when, source, "distinct_ports", int(count)])
        if results["blackholes"] is not None:
            for (when, destination), row in results["blackholes"].iterrows():
                writer.writerow(["possible_blackhole", when, destination,
                                 "unanswered_flows", int(row.unanswered)])


def analyze_csv(input_paths=None):
    """Load and analyze CSV files without writing output files."""
    if input_paths is None:
        paths = [bundled_sample()]
    elif isinstance(input_paths, (str, Path)):
        paths = [Path(input_paths)]
    else:
        paths = [Path(path) for path in input_paths]
    if not paths:
        raise ValueError("Provide at least one CSV file.")

    datasets = [load_flows(path) for path in paths]
    response_present = ["response_bytes" in dataset for dataset in datasets]
    if any(response_present) and not all(response_present):
        raise ValueError("All input files must either include response_bytes or omit it.")
    flows = pd.concat(datasets, ignore_index=True)
    results = analyze(flows)
    return {"flows": flows, "results": results, "report": make_report(flows, results)}


def run_analysis(input_paths=None, output_dir="output"):
    """Analyze CSV files and return the report, findings, and output paths.

    input_paths may be a single path, a sequence of paths, or None for the
    bundled sample. Invalid data raises ValueError; file errors raise OSError.
    """
    analysis = analyze_csv(input_paths)
    flows, results, report = analysis["flows"], analysis["results"], analysis["report"]
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "summary.txt"
    events_path = output_dir / "events.csv"
    chart_path = output_dir / "traffic_overview.png"
    summary_path.write_text(report, encoding="utf-8")
    save_events(results, events_path)
    make_chart(flows, results, chart_path)
    return {"report": report, "results": results, "summary_path": summary_path,
            "events_path": events_path, "chart_path": chart_path}


def main():
    if len(sys.argv) == 1:
        from gui import launch_gui
        launch_gui()
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", nargs="+", type=Path, metavar="CSV",
                        help="One or more flow CSV files (default: bundled sample)")
    parser.add_argument("--output", type=Path, default=Path.cwd() / "output",
                        help="Results directory (default: ./output)")
    parser.add_argument("--regenerate-sample", action="store_true",
                        help="Create a new sample CSV in ./data before analyzing it")
    args = parser.parse_args()

    try:
        if args.regenerate_sample and args.input:
            raise ValueError("Use --regenerate-sample without --input.")
        paths = ([generate_demo_csv(Path.cwd() / "data" / "sample_traffic.csv")]
                 if args.regenerate_sample else args.input)
        output = run_analysis(paths, args.output)
    except (OSError, ValueError, pd.errors.ParserError) as error:
        parser.exit(2, f"Error: {error}\n")

    print(output["report"])
    print(f"Saved summary.txt, events.csv, and traffic_overview.png to {args.output.resolve()}")


if __name__ == "__main__":
    main()
