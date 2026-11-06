# Network Traffic Analyzer

A desktop application for exploring network flow records. It summarizes traffic, plots distributions, and highlights activity that may need investigation. The application works with CSV files and includes a sample dataset.

## Getting started

### Windows executable

Open `dist\NetworkTrafficAnalyzer.exe`. The sample data loads automatically. Select **Open CSV files** to analyze your own data, or **Load sample data** to return to the sample.

The window has three tabs:

- **Traffic charts** shows traffic over time, protocol and port totals, and the distribution of flow sizes. Use the chart toolbar to zoom, pan, or save an image.
- **Flagged events** lists unusual traffic windows and possible port sweeps or blackholes.
- **Summary** shows traffic totals, percentiles, and details of the flagged events.

The executable is generated locally and is excluded from Git. If it is not present, build it using the instructions below.

### Run from source

Install Python 3.10 or newer, then run:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python run.py
```

To build the Windows executable, install PyInstaller and run the build script from the project folder:

```powershell
.venv\Scripts\python -m pip install pyinstaller
.\build_exe.ps1
```

## Input data

Each row represents one network flow. The CSV must include:

| Column | Description |
| --- | --- |
| `timestamp` | Flow start time, for example `2026-10-01T09:20:00` |
| `source_ip` | Source IPv4 or IPv6 address |
| `destination_ip` | Destination IPv4 or IPv6 address |
| `protocol` | Protocol name, such as TCP, UDP, or ICMP |
| `destination_port` | Destination port from 0 to 65535; use 0 for ICMP |
| `packets` | Positive packet count |
| `bytes` | Nonnegative number of bytes sent |
| `response_bytes` | Optional number of bytes observed in response |

Multiple CSV files can be selected together if they use the same schema and cover a continuous capture period. Files are combined before analysis. Missing capture periods within the observed time range may appear as traffic drops.

## Detection rules

Traffic is grouped into five-minute windows. The application flags:

- **Volume spikes:** traffic above the third quartile plus three times the interquartile range of active windows.
- **Traffic drops:** traffic below 25% of the median active window.
- **Possible port sweeps:** a source contacting at least 10 distinct destination ports in one window.
- **Possible blackholes:** at least 10 TCP flows to a destination in one window, with no observed response in at least 90% of those flows. This check requires `response_bytes`.

These flags are prompts for investigation. A missing response can have several causes and does not establish that a network blackhole exists.

## Command line and Python API

For a file-based report, run:

```powershell
.venv\Scripts\python run.py --input traffic.csv --output results
```

This writes a summary, an events CSV, and a chart to the selected output folder. The same analysis can be called from Python:

```python
from run import analyze_csv

analysis = analyze_csv("traffic.csv")
print(analysis["report"])
```

The sample data can be recreated with `python generate_sample_data.py`. It is fictional and contains examples of the events listed above.

## Tests

```powershell
.venv\Scripts\python -m unittest discover -s tests -v
```

The project uses Pandas to prepare and group the records, NumPy for statistics, and Matplotlib for the charts.
