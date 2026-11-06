"""Create reproducible, fictional network flow data for the demo."""

import csv
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np


OUTPUT = Path(__file__).parent / "data" / "sample_traffic.csv"
START = datetime(2026, 10, 1)


def add_flow(rows, timestamp, source, destination, protocol, port, packets, size, response):
    rows.append((timestamp.isoformat(timespec="seconds"), source, destination,
                 protocol, port, packets, size, response))


def generate_sample_csv(output=OUTPUT, seed=42):
    """Write a repeatable demo CSV and return its path."""
    output = Path(output)
    rng = np.random.default_rng(seed)
    rows = []
    sources = [f"192.168.1.{number}" for number in range(10, 40)]
    destinations = [f"203.0.113.{number}" for number in range(1, 16)]
    protocols = ["TCP", "UDP", "ICMP"]

    # One day of ordinary five-minute traffic windows.
    for window in range(24 * 12):
        if window in (11 * 12 + 1, 11 * 12 + 2):
            continue  # Deliberate traffic drop at 11:05 and 11:10.
        window_start = START + timedelta(minutes=5 * window)
        for _ in range(int(rng.poisson(9)) + 3):
            protocol = str(rng.choice(protocols, p=[0.72, 0.23, 0.05]))
            ports = {"TCP": [80, 443, 22, 8080],
                     "UDP": [53, 123, 443], "ICMP": [0]}
            port = int(rng.choice(ports[protocol]))
            size = max(64, int(rng.lognormal(mean=8.1, sigma=0.8)))
            packets = max(1, int(np.ceil(size / rng.integers(500, 1400))))
            response = 0 if rng.random() < 0.03 else int(size * rng.uniform(0.1, 0.8))
            add_flow(rows, window_start + timedelta(seconds=int(rng.integers(0, 300))),
                     str(rng.choice(sources)), str(rng.choice(destinations)),
                     protocol, port, packets, size, response)

    # Two deliberately large traffic bursts.
    for hour, minute in [(9, 20), (18, 45)]:
        burst_start = START + timedelta(hours=hour, minutes=minute)
        for _ in range(70):
            size = int(rng.integers(30_000, 80_000))
            add_flow(rows, burst_start + timedelta(seconds=int(rng.integers(0, 300))),
                     "192.168.1.250", "198.51.100.10", "TCP", 443,
                     int(np.ceil(size / 1000)), size, int(size * 0.2))

    # One source contacts many different ports in a single window.
    scan_start = START + timedelta(hours=13, minutes=30)
    for port in range(20, 40):
        add_flow(rows, scan_start + timedelta(seconds=port),
                 "192.168.1.251", "198.51.100.20", "TCP", port, 2,
                 int(rng.integers(200, 1500)), 100)

    # Many attempts to one destination with no observed response.
    blackhole_start = START + timedelta(hours=16, minutes=10)
    for _ in range(35):
        size = int(rng.integers(500, 2000))
        add_flow(rows, blackhole_start + timedelta(seconds=int(rng.integers(0, 300))),
                 str(rng.choice(sources)), "198.51.100.30", "TCP", 443,
                 2, size, 0)

    rows.sort(key=lambda row: row[0])
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["timestamp", "source_ip", "destination_ip", "protocol",
                         "destination_port", "packets", "bytes", "response_bytes"])
        writer.writerows(rows)
    return output


if __name__ == "__main__":
    path = generate_sample_csv()
    print(f"Created sample data in {path}")
