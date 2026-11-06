"""Desktop interface for exploring network flow records."""

import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk

from analyze_traffic import create_chart
from run import analyze_csv


class TrafficApp:
    def __init__(self, root):
        self.root = root
        root.title("Network Traffic Analyzer")
        root.geometry("1250x850")
        root.minsize(850, 600)
        self.messages = queue.Queue()
        self.figure = self.canvas = self.toolbar = None

        style = ttk.Style(root)
        style.configure("Title.TLabel", font=("Segoe UI", 20, "bold"))
        style.configure("Metric.TLabel", font=("Segoe UI", 12, "bold"))
        style.configure("Treeview", rowheight=26)

        outer = ttk.Frame(root, padding=16)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="Network Traffic Analyzer", style="Title.TLabel").pack(anchor="w")
        ttk.Label(outer, text="Explore traffic, identify unusual patterns, and inspect the details.").pack(anchor="w", pady=(2, 10))

        controls = ttk.Frame(outer)
        controls.pack(fill="x", pady=(0, 8))
        self.open_button = ttk.Button(controls, text="Open CSV files", command=self.open_files)
        self.open_button.pack(side="left")
        self.sample_button = ttk.Button(controls, text="Load sample data", command=self.load_sample)
        self.sample_button.pack(side="left", padx=8)
        self.status = tk.StringVar(value="Loading sample data...")
        ttk.Label(controls, textvariable=self.status).pack(side="left", padx=8)

        self.metrics = tk.StringVar()
        ttk.Label(outer, textvariable=self.metrics, style="Metric.TLabel").pack(anchor="w", pady=(2, 8))
        tabs = ttk.Notebook(outer)
        tabs.pack(fill="both", expand=True)
        chart_tab, events_tab, summary_tab = (ttk.Frame(tabs, padding=8) for _ in range(3))
        tabs.add(chart_tab, text="  Traffic charts  ")
        tabs.add(events_tab, text="  Flagged events  ")
        tabs.add(summary_tab, text="  Summary  ")

        self.chart_container = ttk.Frame(chart_tab)
        self.chart_container.pack(fill="both", expand=True)
        self.event_note = tk.StringVar(value="Flags are indicators for investigation.")
        ttk.Label(events_tab, textvariable=self.event_note).pack(anchor="w", pady=(0, 8))
        table_frame = ttk.Frame(events_tab)
        table_frame.pack(fill="both", expand=True)
        self.events = ttk.Treeview(table_frame, columns=("type", "time", "subject", "detail"), show="headings")
        for key, label, width in [("type", "Event", 150), ("time", "Window start", 175),
                                  ("subject", "Source / destination", 200), ("detail", "Details", 300)]:
            self.events.heading(key, text=label)
            self.events.column(key, width=width, minwidth=100, stretch=True)
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.events.yview)
        self.events.configure(yscrollcommand=scrollbar.set)
        self.events.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.summary = scrolledtext.ScrolledText(summary_tab, wrap="word", font=("Consolas", 10))
        self.summary.pack(fill="both", expand=True)
        self.summary.configure(state="disabled")
        root.after(100, self.load_sample)
        root.after(100, self.poll_messages)

    def open_files(self):
        paths = filedialog.askopenfilenames(title="Select network flow CSV files",
                                           filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if paths:
            label = Path(paths[0]).name if len(paths) == 1 else f"{len(paths)} CSV files"
            self.start_analysis(paths, label)

    def load_sample(self):
        self.start_analysis(None, "sample data")

    def start_analysis(self, paths, label):
        self.open_button.configure(state="disabled")
        self.sample_button.configure(state="disabled")
        self.status.set(f"Analyzing {label}...")

        def worker():
            try:
                self.messages.put((label, analyze_csv(paths), None))
            except Exception as error:
                self.messages.put((label, None, str(error)))

        threading.Thread(target=worker, daemon=True).start()

    def poll_messages(self):
        try:
            label, analysis, error = self.messages.get_nowait()
        except queue.Empty:
            pass
        else:
            self.open_button.configure(state="normal")
            self.sample_button.configure(state="normal")
            if error:
                self.status.set("Analysis failed; previous results are still shown.")
                messagebox.showerror("Could not analyze CSV", error, parent=self.root)
            else:
                try:
                    self.show_analysis(label, analysis)
                except Exception as error:
                    self.status.set("Could not display the results.")
                    messagebox.showerror("Display error", str(error), parent=self.root)
        self.root.after(100, self.poll_messages)

    def show_analysis(self, label, analysis):
        flows, results = analysis["flows"], analysis["results"]
        blackholes = results["blackholes"]
        count = (len(results["spikes"]) + len(results["drops"]) + len(results["sweeps"])
                 + (len(blackholes) if blackholes is not None else 0))
        self.metrics.set(f"{len(flows):,} flows     |     {flows['bytes'].sum() / 1_000_000:,.2f} MB"
                         f"     |     {count} flagged events")
        self.status.set(f"Showing {label}")
        self.summary.configure(state="normal")
        self.summary.delete("1.0", "end")
        self.summary.insert("1.0", analysis["report"])
        self.summary.configure(state="disabled")
        self.events.delete(*self.events.get_children())
        for when, size in results["spikes"].items():
            self.events.insert("", "end", values=("Volume spike", str(when), "All traffic", f"{size / 1_000_000:.2f} MB"))
        for when, size in results["drops"].items():
            self.events.insert("", "end", values=("Traffic drop", str(when), "All traffic", f"{size / 1_000_000:.3f} MB"))
        for (when, source), ports in results["sweeps"].items():
            self.events.insert("", "end", values=("Port sweep", str(when), source, f"{ports} distinct ports"))
        if blackholes is not None:
            for (when, destination), row in blackholes.iterrows():
                detail = f"{int(row.unanswered)} of {int(row.flows)} unanswered"
                self.events.insert("", "end", values=("Possible blackhole", str(when), destination, detail))
        self.event_note.set("Flags are indicators for investigation." if blackholes is not None else
                            "Blackhole check unavailable: CSV has no response_bytes column.")

        if self.toolbar is not None:
            self.toolbar.destroy()
            self.canvas.get_tk_widget().destroy()
            plt.close(self.figure)
        self.figure = create_chart(flows, results)
        self.canvas = FigureCanvasTkAgg(self.figure, master=self.chart_container)
        self.toolbar = NavigationToolbar2Tk(self.canvas, self.chart_container, pack_toolbar=False)
        self.toolbar.update()
        self.toolbar.pack(side="bottom", fill="x")
        self.canvas.get_tk_widget().pack(side="top", fill="both", expand=True)
        self.canvas.draw()


def launch_gui():
    root = tk.Tk()
    TrafficApp(root)
    root.mainloop()


if __name__ == "__main__":
    launch_gui()
