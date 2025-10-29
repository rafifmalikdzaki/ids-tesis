#!/usr/bin/env python3
"""
Beautiful TUI for RSS visualization using textual and rich libraries
"""

import os
import sys
import time
import signal
import json
import subprocess
import argparse
from collections import deque
from datetime import datetime

try:
    from textual.app import App, ComposeResult
    from textual.containers import Container, Horizontal, Vertical
    from textual.widgets import Header, Footer, Static, ProgressBar, DataTable, Log
    from textual.reactive import Reactive
    from textual.binding import Binding
    from textual.events import Key, Mount
    from rich.style import Style
    from rich.text import Text
    from rich.panel import Panel
    from rich.table import Table
    from rich.bar import Bar
    from rich.align import Align
    from rich.console import Console
except ImportError as e:
    print(f"Error: {e}")
    print("Install required libraries with: pip install textual rich")
    sys.exit(1)

class RSSDataTable(Static):
    """Custom widget for RSS data table"""

    def __init__(self):
        super().__init__()
        self.current_data = {}
        self.packet_rates = [0] * 8
        self.bucket_colors = ["bright_blue", "bright_green", "bright_yellow", "bright_red",
                              "bright_magenta", "bright_cyan", "white", "orange1"]

    def update_data(self, data, rates):
        self.current_data = data
        self.packet_rates = rates
        self.refresh()

    def render(self):
        total = sum(self.current_data.values()) if self.current_data else 1

        table = Table(show_header=True, box="ROUNDED")
        table.add_column("Bucket", justify="center", style="bold")
        table.add_column("Packets", justify="right", style="cyan")
        table.add_column("%", justify="center", style="green")
        table.add_column("Distribution", justify="left")
        table.add_column("Rate", justify="right", style="yellow")

        for i in range(8):
            count = self.current_data.get(i, 0)
            percentage = (count / total) * 100
            rate = self.packet_rates[i]

            # Visual bar
            bar_length = int(percentage / 2)
            bar = "█" * bar_length

            table.add_row(
                f"[{self.bucket_colors[i]}]{i}[/]",
                f"{count:,}",
                f"{percentage:5.1f}%",
                bar,
                f"{rate:.1f} p/s"
            )

        return table

class DistributionChart(Static):
    """Distribution chart widget"""

    def __init__(self):
        super().__init__()
        self.current_data = {}

    def update_data(self, data):
        self.current_data = data
        self.refresh()

    def render(self):
        if not self.current_data:
            return Panel("No data yet...", title="📊 Distribution")

        values = list(self.current_data.values())
        max_val = max(values) if values else 1

        # Create bar chart
        chart = Bar()
        colors = ["bright_blue", "bright_green", "bright_yellow", "bright_red",
                  "bright_magenta", "bright_cyan", "white", "orange1"]

        for i, value in enumerate(self.current_data.values()):
            chart.add_bar(f"[{colors[i]}]Bucket {i}[/]", value)

        # Statistics
        total = sum(self.current_data.values())
        if total > 0:
            avg = total / len(values)
            max_val = max(values)
            min_val = min(values)
            balance_score = self.calculate_balance_score()

            stats = f"""📊 Statistics
Total: {total:,} packets
Average: {avg:.1f}/bucket
Range: {min_val} - {max_val}
Balance Score: {balance_score:.1f}%"""
        else:
            stats = "No packets yet"

        return Panel(stats, title="📈 Distribution Analysis")

    def calculate_balance_score(self):
        if not self.current_data:
            return 0

        total = sum(self.current_data.values())
        if total == 0:
            return 0

        ideal = total / len(self.current_data)
        variance = sum((count - ideal) ** 2 for count in self.current_data.values())
        return max(0, 100 - (variance / (total * total)) * 100)

class HistoryPanel(Static):
    """History panel widget"""

    def __init__(self):
        super().__init__()
        self.total_history = deque(maxlen=30)

    def add_data_point(self, total):
        self.total_history.append(total)
        self.refresh()

    def render(self):
        if len(self.total_history) < 2:
            return Panel("📈 History (will appear here...)", title="Packet History")

        # Create ASCII chart
        values = list(self.total_history)
        max_val = max(values) if values else 1

        chart_lines = []
        for height in range(5, 0, -1):
            line = ""
            for val in values[-20:]:  # Last 20 points
                normalized = (val / max_val) * 15
                if normalized >= height:
                    line += "█"
                else:
                    line += " "
            chart_lines.append(line)

        chart_text = f"📈 Total Packets (Last 20 Updates)\n" + "\n".join(chart_lines)
        return Panel(chart_text, title="📊 Traffic History")

class RSSTUI(App):
    """Main TUI application"""

    CSS = """
    Screen {
        layout: vertical;
    }

    Header {
        height: 3;
        background: $background 90%;
        color: $text;
        text-align: center;
        content: center;
    }

    Main {
        height: 1fr;
        layout: horizontal;
    }

    LeftPanel {
        width: 70%;
        layout: vertical;
    }

    RightPanel {
        width: 30%;
        layout: vertical;
    }

    DataTable {
        height: 1fr;
    }

    Distribution {
        height: 1fr;
    }

    Rates {
        height: 1fr;
    }

    History {
        height: 1fr;
    }

    Footer {
        height: 3;
        background: $background 90%;
        color: $text;
        text-align: center;
    }
    """

    def __init__(self, interface="lo", max_buckets=8, refresh_rate=1.0):
        super().__init__()
        self.interface = interface
        self.max_buckets = max_buckets
        self.refresh_rate = refresh_rate
        self.running = True
        self.map_id = None

        # Data storage
        self.current_data = {}
        self.packet_rates = [0] * max_buckets
        self.last_counters = {}
        self.total_packets = 0
        self.last_update_time = time.time()

    def on_mount(self) -> None:
        """Initialize widgets"""
        self.title = f"🚀 Software RSS Monitor - {self.interface}"
        self.set_interval(self.update_data, self.refresh_rate)
        self.set_interval(self.update_display, self.refresh_rate)

    def compose(self) -> ComposeResult:
        """Compose the UI"""
        yield Header(self.title, style="bold blue")

        with Container(id="main"):
            with Horizontal():
                with Container(id="left"):
                    yield DataTable(id="table")
                    yield DistributionChart(id="distribution")
                    yield Container(id="rates", Static("📈 Packet Rates\nComing soon..."))
                with Container(id="right"):
                    yield HistoryPanel(id="history")

        yield Footer("Press Ctrl+C to exit • Refresh: 1s • Interface: " + self.interface)

    async def update_data(self):
        """Update data from BPF maps"""
        if not self.map_id:
            self.map_id = self.find_map_id('bucket_counters')
            if not self.map_id:
                return

        # Read current counters
        current_counters = self.read_map_values()

        # Calculate rates
        current_time = time.time()
        elapsed = current_time - self.last_update_time
        if elapsed > 0:
            for i in range(self.max_buckets):
                current = current_counters.get(i, 0)
                last = self.last_counters.get(i, 0)
                rate = (current - last) / elapsed
                self.packet_rates[i] = rate

        self.last_counters = current_counters.copy()
        self.current_data = current_counters
        self.total_packets = sum(current_counters.values())
        self.last_update_time = current_time

        # Update history
        self.query_one("#history").add_data_point(self.total_packets)

    async def update_display(self):
        """Update display widgets"""
        table = self.query_one("#table")
        distribution = self.query_one("#distribution")

        table.update_data(self.current_data, self.packet_rates)
        distribution.update_data(self.current_data)

    def find_map_id(self, map_name):
        """Find map ID"""
        try:
            cmd = ['sudo-rs', 'bpftool', 'map', 'list']
            result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=2)
            stdout = result.stdout.strip()

            for line in stdout.split('\n'):
                if map_name in line:
                    parts = line.split(':')
                    if len(parts) > 0:
                        try:
                            return int(parts[0])
                        except ValueError:
                            continue
        except:
            pass
        return None

    def read_map_values(self):
        """Read map values"""
        if not self.map_id:
            return {}

        try:
            cmd = ['sudo-rs', 'bpftool', 'map', 'dump', 'id', str(self.map_id), '-j']
            result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=2)
            stdout = result.stdout.strip()

            if not stdout:
                return {}

            data = json.loads(stdout)
            values = {}
            for entry in data:
                if 'formatted' in entry:
                    formatted = entry['formatted']
                    key = formatted['key']
                    total_value = sum(cpu_value['value'] for cpu_value in formatted['values'])
                    values[key] = total_value
            return values
        except:
            return {}

def main():
    parser = argparse.ArgumentParser(description='Beautiful RSS TUI Monitor')
    parser.add_argument('-i', '--interface', default='lo', help='Interface (default: lo)')
    parser.add_argument('-b', '--buckets', type=int, default=8, help='Buckets (default: 8)')
    parser.add_argument('-r', '--refresh', type=float, default=1.0, help='Refresh rate in seconds (default: 1.0)')

    args = parser.parse_args()

    app = RSSTUI(
        interface=args.interface,
        max_buckets=args.buckets,
        refresh_rate=args.refresh
    )

    app.run()

if __name__ == '__main__':
    main()