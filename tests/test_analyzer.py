"""Behavior checks for CSV validation, detection, and the command-line runner."""

import csv
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analyze_traffic import analyze, load_flows, make_chart, make_report
from run import generate_demo_csv, run_analysis


SAMPLE = ROOT / "data" / "sample_traffic.csv"
ROW = {"timestamp": "2026-10-01T12:00:00", "source_ip": "192.0.2.1",
       "destination_ip": "198.51.100.1", "protocol": "TCP",
       "destination_port": 443, "packets": 1, "bytes": 100,
       "response_bytes": 10}


def write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=ROW.keys())
        writer.writeheader()
        writer.writerows(rows)


class TrafficAnalyzerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_root = ROOT / "output"
        cls.temp_root.mkdir(exist_ok=True)

    def test_sample_detects_known_events(self):
        results = analyze(load_flows(SAMPLE))
        self.assertEqual([time.strftime("%H:%M") for time in results["spikes"].index],
                         ["09:20", "18:45"])
        self.assertEqual([time.strftime("%H:%M") for time in results["drops"].index],
                         ["11:05", "11:10"])
        self.assertEqual(len(results["sweeps"]), 1)
        self.assertEqual(len(results["blackholes"]), 1)
        self.assertEqual(results["blackholes"].index[0][1], "198.51.100.30")

    def test_without_response_column_is_explicitly_unavailable(self):
        with tempfile.TemporaryDirectory(dir=self.temp_root) as directory:
            path = Path(directory) / "flows.csv"
            with path.open("w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(file, fieldnames=list(ROW)[:-1])
                writer.writeheader()
                writer.writerow({key: value for key, value in ROW.items()
                                 if key != "response_bytes"})
            results = analyze(load_flows(path))
            self.assertIsNone(results["blackholes"])
            self.assertIn("Unavailable", make_report(load_flows(path), results))

    def test_rejects_bad_numeric_and_ip_values(self):
        bad_values = [("bytes", "inf"), ("bytes", "1.5"),
                      ("response_bytes", "NaN"), ("destination_port", "443.5"),
                      ("source_ip", "not-an-ip")]
        with tempfile.TemporaryDirectory(dir=self.temp_root) as directory:
            path = Path(directory) / "bad.csv"
            for column, value in bad_values:
                with self.subTest(column=column, value=value):
                    write_csv(path, [{**ROW, column: value}])
                    with self.assertRaises(ValueError):
                        load_flows(path)

    def test_zero_traffic_still_produces_report_and_chart(self):
        with tempfile.TemporaryDirectory(dir=self.temp_root) as directory:
            path = Path(directory) / "zero.csv"
            chart = Path(directory) / "chart.png"
            write_csv(path, [{**ROW, "bytes": 0, "response_bytes": 0}])
            flows = load_flows(path)
            results = analyze(flows)
            self.assertTrue(results["spikes"].empty)
            self.assertTrue(results["drops"].empty)
            self.assertIn("Total traffic: 0.00 MB", make_report(flows, results))
            make_chart(flows, results, chart)
            self.assertTrue(chart.is_file())

    def test_blackhole_rule_ignores_udp(self):
        with tempfile.TemporaryDirectory(dir=self.temp_root) as directory:
            path = Path(directory) / "udp.csv"
            write_csv(path, [{**ROW, "protocol": "udp", "response_bytes": 0} for _ in range(10)])
            results = analyze(load_flows(path))
            self.assertTrue(results["blackholes"].empty)

    def test_runner_saves_all_outputs(self):
        with tempfile.TemporaryDirectory(dir=self.temp_root) as directory:
            completed = subprocess.run(
                [sys.executable, str(ROOT / "run.py"), "--input", str(SAMPLE),
                 "--output", directory], capture_output=True, text=True,
                check=False, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            for name in ["summary.txt", "events.csv", "traffic_overview.png"]:
                self.assertTrue((Path(directory) / name).is_file(), name)

    def test_python_api_generates_and_analyzes(self):
        with tempfile.TemporaryDirectory(dir=self.temp_root) as directory:
            path = Path(directory) / "sample.csv"
            generate_demo_csv(path)
            first = path.read_bytes()
            generate_demo_csv(path)
            self.assertEqual(path.read_bytes(), first)
            output = run_analysis(path, Path(directory) / "results")
            self.assertTrue(output["events_path"].is_file())
            self.assertEqual(len(output["results"]["blackholes"]), 1)
            with self.assertRaises(ValueError):
                run_analysis([], Path(directory) / "unused")

    def test_python_api_rejects_mixed_response_schemas(self):
        with tempfile.TemporaryDirectory(dir=self.temp_root) as directory:
            full = Path(directory) / "full.csv"
            partial = Path(directory) / "partial.csv"
            write_csv(full, [ROW])
            with partial.open("w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(file, fieldnames=list(ROW)[:-1])
                writer.writeheader()
                writer.writerow({key: value for key, value in ROW.items()
                                 if key != "response_bytes"})
            with self.assertRaisesRegex(ValueError, "response_bytes"):
                run_analysis([full, partial], Path(directory) / "unused")

    def test_python_api_combines_two_csv_files(self):
        with tempfile.TemporaryDirectory(dir=self.temp_root) as directory:
            first = Path(directory) / "first.csv"
            second = Path(directory) / "second.csv"
            write_csv(first, [ROW])
            write_csv(second, [{**ROW, "timestamp": "2026-10-01T12:05:00",
                                "bytes": 200}])
            output = run_analysis([first, second], Path(directory) / "results")
            self.assertIn("Flows: 2", output["report"])
            self.assertEqual(output["results"]["traffic"].sum(), 300)


if __name__ == "__main__":
    unittest.main()
