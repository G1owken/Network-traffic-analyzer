"""Summarize network flows and flag unusual five-minute windows."""

from ipaddress import ip_address

import matplotlib
matplotlib.use("Agg")  # Save charts without requiring a desktop display.
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


REQUIRED = {"timestamp", "source_ip", "destination_ip", "protocol",
            "destination_port", "packets", "bytes"}


def load_flows(path):
    flows = pd.read_csv(path, dtype={"source_ip": "string", "destination_ip": "string",
                                     "protocol": "string"})
    return validate_flows(flows)


def validate_flows(flows):
    flows = flows.copy()
    missing = REQUIRED - set(flows.columns)
    if missing:
        raise ValueError(f"Missing columns: {', '.join(sorted(missing))}")
    if flows.empty:
        raise ValueError("The CSV has no traffic rows.")
    checked = list(REQUIRED) + (["response_bytes"] if "response_bytes" in flows else [])
    if flows[checked].isna().any().any():
        raise ValueError("Required columns contain blank values.")
    for column in ("source_ip", "destination_ip", "protocol"):
        flows[column] = flows[column].astype("string")
        flows[column] = flows[column].str.strip()
        if flows[column].eq("").any():
            raise ValueError(f"{column} must not be blank.")
    flows["protocol"] = flows["protocol"].str.upper()

    flows["timestamp"] = pd.to_datetime(flows["timestamp"], errors="raise")
    if flows["timestamp"].isna().any():
        raise ValueError("Timestamps must be valid dates and times.")
    for column in ["destination_port", "packets", "bytes"] + (["response_bytes"] if "response_bytes" in flows else []):
        flows[column] = pd.to_numeric(flows[column], errors="raise")
        if not np.isfinite(flows[column].to_numpy()).all():
            raise ValueError(f"{column} must contain finite numbers.")
        if (flows[column] % 1 != 0).any():
            raise ValueError(f"{column} must contain whole numbers.")
    if (flows["bytes"] < 0).any() or (flows["packets"] <= 0).any():
        raise ValueError("Bytes must be nonnegative and packets must be positive.")
    if (~flows["destination_port"].between(0, 65535)).any():
        raise ValueError("Destination ports must be between 0 and 65535.")
    if "response_bytes" in flows and (flows["response_bytes"] < 0).any():
        raise ValueError("Response bytes must be nonnegative.")
    for column in ("source_ip", "destination_ip"):
        for address in flows[column].unique():
            try:
                ip_address(address)
            except ValueError as error:
                raise ValueError(f"Invalid {column}: {address}") from error
    return flows


def analyze(flows):
    flows = flows.copy()
    flows["window"] = flows["timestamp"].dt.floor("5min")
    traffic = flows.groupby("window")["bytes"].sum().sort_index()
    all_windows = pd.date_range(traffic.index.min(), traffic.index.max(), freq="5min")
    traffic = traffic.reindex(all_windows, fill_value=0)

    # Tukey's upper fence, using only windows with traffic so idle periods
    # do not make normal activity look unusual.
    active = traffic[traffic > 0].to_numpy()
    q1, q3 = np.percentile(active, [25, 75]) if len(active) else (0, 0)
    spike_threshold = q3 + 3 * (q3 - q1)
    spikes = traffic[traffic > spike_threshold]
    drop_threshold = 0.25 * np.median(active) if len(active) else 0
    drops = traffic[traffic < drop_threshold]

    distinct_ports = flows.groupby(["window", "source_ip"])["destination_port"].nunique()
    port_sweeps = distinct_ports[distinct_ports >= 10].sort_values(ascending=False)
    protocol_bytes = flows.groupby("protocol")["bytes"].sum().sort_values(ascending=False)
    port_bytes = flows.groupby("destination_port")["bytes"].sum().nlargest(6)
    source_bytes = flows.groupby("source_ip")["bytes"].sum().sort_values(ascending=False)
    blackholes = None
    if "response_bytes" in flows:
        tcp = flows[flows["protocol"] == "TCP"]
        attempts = tcp.assign(unanswered=tcp["response_bytes"].eq(0)).groupby(
            ["window", "destination_ip"]
        ).agg(flows=("bytes", "size"), unanswered=("unanswered", "sum"))
        blackholes = attempts[(attempts["flows"] >= 10) &
                              (attempts["unanswered"] / attempts["flows"] >= 0.9)]
    return {"traffic": traffic, "spikes": spikes, "spike_threshold": spike_threshold,
            "drops": drops, "drop_threshold": drop_threshold,
            "sweeps": port_sweeps, "blackholes": blackholes,
            "protocol_bytes": protocol_bytes, "port_bytes": port_bytes,
            "source_bytes": source_bytes}


def make_report(flows, results):
    traffic = results["traffic"]
    spikes = results["spikes"]
    sweeps = results["sweeps"]
    protocol_bytes = results["protocol_bytes"]
    source_bytes = results["source_bytes"]
    sizes = flows["bytes"].to_numpy()
    lines = [
        "NETWORK TRAFFIC SUMMARY",
        f"Period: {flows['timestamp'].min()} to {flows['timestamp'].max()}",
        f"Flows: {len(flows):,}",
        f"Packets: {flows['packets'].sum():,}",
        f"Total traffic: {sizes.sum() / 1_000_000:,.2f} MB",
        f"Median flow size: {np.median(sizes):,.0f} bytes",
        f"95th percentile flow size: {np.percentile(sizes, 95):,.0f} bytes",
        f"Busiest 5-minute window: {traffic.idxmax()} ({traffic.max() / 1_000_000:.2f} MB)",
        f"Busiest source: {source_bytes.index[0]} ({source_bytes.iloc[0] / 1_000_000:.2f} MB)",
        "",
        "TRAFFIC BY PROTOCOL",
    ]
    total_bytes = sizes.sum()
    lines += [f"  {name}: {amount / 1_000_000:.2f} MB ({amount / total_bytes if total_bytes else 0:.1%})"
              for name, amount in protocol_bytes.items()]
    lines += ["", f"VOLUME SPIKES (5-minute bytes > {results['spike_threshold'] / 1_000_000:.2f} MB)"]
    lines += [f"  {when}: {amount / 1_000_000:.2f} MB"
              for when, amount in spikes.items()] or ["  None"]
    lines += ["", f"TRAFFIC DROPS (5-minute bytes < {results['drop_threshold'] / 1_000_000:.3f} MB)"]
    lines += [f"  {when}: {amount / 1_000_000:.3f} MB"
              for when, amount in results["drops"].items()] or ["  None"]
    lines += ["", "POSSIBLE PORT SWEEPS (10+ destination ports per source in 5 minutes)"]
    lines += [f"  {when}, {source}: {count} ports"
              for (when, source), count in sweeps.items()] or ["  None"]
    lines += ["", "POSSIBLE BLACKHOLES (10+ TCP flows to one destination, 90%+ without response)"]
    if results["blackholes"] is None:
        lines += ["  Unavailable: add response_bytes to the CSV."]
    else:
        lines += [f"  {when}, {destination}: {int(row.flows)} flows, {int(row.unanswered)} unanswered"
                  for (when, destination), row in results["blackholes"].iterrows()] or ["  None"]
    lines += ["", "These are simple statistical flags, not proof of malicious activity."]
    return "\n".join(lines) + "\n"


def create_chart(flows, results):
    traffic = results["traffic"]
    spikes = results["spikes"]
    drops = results["drops"]
    protocol_bytes = results["protocol_bytes"]
    port_bytes = results["port_bytes"]
    plt.style.use("seaborn-v0_8-whitegrid")
    fig, axes = plt.subplots(2, 2, figsize=(13, 9), layout="constrained")
    fig.suptitle("Network Traffic Overview", fontsize=17, fontweight="bold")

    ax = axes[0, 0]
    ax.plot(traffic.index, traffic.to_numpy() / 1_000_000, color="#2474a6", linewidth=1)
    ax.scatter(spikes.index, spikes.to_numpy() / 1_000_000, color="#d35445",
               label="Volume spike", zorder=3)
    ax.scatter(drops.index, drops.to_numpy() / 1_000_000, color="#7756a8",
               label="Traffic drop", zorder=3)
    ax.set(title="Traffic over time", ylabel="MB per 5 minutes")
    if not spikes.empty or not drops.empty:
        ax.legend()
    ax.tick_params(axis="x", labelrotation=30)

    ax = axes[0, 1]
    ax.bar(protocol_bytes.index, protocol_bytes.to_numpy() / 1_000_000, color="#39a78e")
    ax.set(title="Traffic by protocol", ylabel="Total MB")

    ax = axes[1, 0]
    ax.bar(port_bytes.index.astype(str), port_bytes.to_numpy() / 1_000_000,
           color="#dc9860")
    ax.set(title="Top destination ports", xlabel="Port", ylabel="Total MB")

    ax = axes[1, 1]
    flow_bytes = flows["bytes"].to_numpy()
    positive = flow_bytes[flow_bytes > 0]
    if len(positive):
        bins = (np.logspace(np.log10(positive.min()), np.log10(positive.max()), 30)
                if positive.min() < positive.max() else 1)
        ax.hist(positive, bins=bins, color="#8e75b5")
        ax.set_xscale("log")
    ax.set(title="Flow size distribution", xlabel="Bytes per flow (log scale)",
           ylabel="Number of flows")

    return fig


def make_chart(flows, results, path):
    fig = create_chart(flows, results)
    fig.savefig(path, dpi=150)
    plt.close(fig)


