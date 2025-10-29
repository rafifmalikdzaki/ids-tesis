#!/usr/bin/env python3
"""
Beautiful TUI for RSS visualization using rich library
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
    from rich.console import Console
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.progress import Progress, BarColumn, TextColumn
    from rich.table import Table
    from rich.live import Live
    from rich.text import Text
    from rich.align import Align
    from rich.chart import Bar
    from rich import box
    from rich.style import Style
    from rich.color import Color
except ImportError:
    print("Error: rich library not found. Install with: pip install rich")
    sys.exit(1)

class RSSTUI:
    def __init__(self, interface="lo", max_buckets=8, refresh_rate=1.0):
        self.interface = interface
        self.max_buckets = max_buckets
        self.refresh_rate = refresh_rate
        self.running = True
        self.map_id = None

        # Initialize rich components
        self.console = Console()

        # Data storage
        self.current_data = {}
        self.history = deque(maxlen=60)  # 60 seconds of history
        self.packet_rates = [0] * max_buckets
        self.total_packets_history = deque(maxlen=60)

        # Colors for buckets
        self.bucket_colors = [
            "bright_blue", "bright_green", "bright_yellow", "bright_red",
            "bright_magenta", "bright_cyan", "white", "orange1"
        ]

        # Setup signal handler
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        self.running = False

    def run_bpftool(self, args):
        """Run bpftool command"""
        try:
            cmd = ['sudo-rs', 'bpftool'] + args
            result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=2)
            return result.stdout.strip(), result.stderr.strip()
        except:
            return "", "Error"

    def find_map_id(self, map_name):
        """Find map ID"""
        if self.map_id:
            return self.map_id

        stdout, _ = self.run_bpftool(['map', 'list'])
        if not stdout:
            return None

        for line in stdout.split('\n'):
            if map_name in line:
                parts = line.split(':')
                if len(parts) > 0:
                    try:
                        self.map_id = int(parts[0])
                        return self.map_id
                    except ValueError:
                        continue
        return None

    def read_map_values(self):
        """Read map values"""
        if not self.map_id:
            return {}

        stdout, _ = self.run_bpftool(['map', 'dump', 'id', str(self.map_id), '-j'])
        if not stdout:
            return {}

        values = {}
        try:
            data = json.loads(stdout)
            for entry in data:
                if 'formatted' in entry:
                    formatted = entry['formatted']
                    key = formatted['key']
                    total_value = sum(cpu_value['value'] for cpu_value in formatted['values'])
                    values[key] = total_value
        except:
            pass

        return values

    def create_header(self):
        """Create header panel"""
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        header_text = f"""
🚀 Software RSS Monitor - {self.interface}
📊 Total Buckets: {self.max_buckets} | 🕒 {now}
        """.strip()
        return Panel(header_text, box=box.ROUNDED, style="bold blue")

    def create_stats_table(self):
        """Create statistics table"""
        table = Table(title="📈 RSS Statistics", box=box.ROUNDED, show_header=True)
        table.add_column("Bucket", justify="center", style="bold")
        table.add_column("Packets", justify="right", style="cyan")
        table.add_column("Percentage", justify="center", style="green")
        table.add_column("Visual", justify="left")
        table.add_column("Rate", justify="right", style="yellow")

        total = sum(self.current_data.values()) if self.current_data else 1

        for i in range(self.max_buckets):
            count = self.current_data.get(i, 0)
            percentage = (count / total) * 100
            rate = self.packet_rates[i]

            # Create visual bar
            bar_length = int(percentage / 2)
            bar = "█" * bar_length
            if bar_length < 50:  # Add color to short bars
                bar = f"[{self.bucket_colors[i]}]{bar}[/]"

            # Rate formatting
            rate_str = f"{rate:.1f}" if rate > 0 else "0.0"

            table.add_row(
                f"[{self.bucket_colors[i]}]{i}[/]",
                f"{count:,}",
                f"{percentage:5.1f}%",
                bar,
                f"{rate_str} p/s"
            )

        return table

    def create_distribution_chart(self):
        """Create distribution chart"""
        if not self.current_data:
            return Panel("No data yet...", box=box.ROUNDED)

        # Create bar chart
        chart = Bar()
        for i in range(self.max_buckets):
            count = self.current_data.get(i, 0)
            chart.add_bar(str(i), count, style=self.bucket_colors[i])

        # Calculate stats
        total = sum(self.current_data.values())
        if total > 0:
            values = list(self.current_data.values())
            avg = total / len(values)
            max_val = max(values)
            min_val = min(values)

            stats_text = f"""
📊 Distribution Stats:
  Total: {total:,} packets
  Average: {avg:.1f} packets/bucket
  Range: {min_val} - {max_val}
  Balance Score: {self.calculate_balance_score():.1f}%
            """.strip()
        else:
            stats_text = "No packets processed yet"

        return Panel(stats_text, box=box.ROUNDED, title="📈 Distribution Analysis")

    def calculate_balance_score(self):
        """Calculate load balance score"""
        if not self.current_data:
            return 0

        total = sum(self.current_data.values())
        if total == 0:
            return 0

        ideal = total / self.max_buckets
        variance = sum((count - ideal) ** 2 for count in self.current_data.values())
        return max(0, 100 - (variance / (total * total)) * 100)

    def create_rate_chart(self):
        """Create rate chart"""
        if not self.packet_rates or max(self.packet_rates) == 0:
            return Panel("No rate data yet...", box=box.ROUNDED)

        table = Table(title="📈 Packet Rates (p/s)", box=box.ROUNDED)
        table.add_column("Bucket", justify="center")
        table.add_column("Rate", justify="right")
        table.add_column("Visual", justify="left")

        max_rate = max(self.packet_rates)
        for i, rate in enumerate(self.packet_rates):
            bar_length = int((rate / max_rate) * 20) if max_rate > 0 else 0
            bar = "▓" * bar_length
            table.add_row(f"[{self.bucket_colors[i]}]{i}[/]", f"{rate:.1f}", bar)

        return table

    def create_history_panel(self):
        """Create history panel"""
        if len(self.total_packets_history) < 2:
            return Panel("History will appear here...", box=box.ROUNDED)

        # Create simple line chart using text
        history_values = list(self.total_packets_history)
        max_val = max(history_values) if history_values else 1

        # Create ASCII chart
        chart_lines = []
        for height in range(5, 0, -1):
            line = ""
            for val in history_values[-20:]:  # Last 20 data points
                normalized = (val / max_val) * 10
                char_height = int(normalized)
                if char_height >= height:
                    line += "█"
                else:
                    line += " "
            chart_lines.append(line)

        chart_text = "📈 Total Packets (last 20 updates)\n" + "\n".join(chart_lines)
        return Panel(chart_text, box=box.ROUNDED)

    def create_layout(self):
        """Create the main layout"""
        layout = Layout()

        # Header (top)
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main")
        )

        # Main content
        layout["main"].split_row(
            Layout(name="left", size=70),
            Layout(name="right", size=30)
        )

        # Left side - stats and charts
        layout["left"].split_column(
            Layout(name="stats", size=12),
            Layout(name="distribution", size=8),
            Layout(name="rates", size=10)
        )

        # Right side - history
        layout["right"].split_column(
            Layout(name="history", ratio=1)
        )

        # Assign components
        layout["header"].update(Panel(self.create_header(), box=box.ROUNDED))
        layout["left"]["stats"].update(Panel(self.create_stats_table(), box=box.ROUNDED))
        layout["left"]["distribution"].update(self.create_distribution_chart())
        layout["left"]["rates"].update(Panel(self.create_rate_chart(), box=box.ROUNDED))
        layout["right"]["history"].update(self.create_history_panel())

        return layout

    def update_data(self):
        """Update data for display"""
        # Read current counters
        current_counters = self.read_map_values()

        # Calculate rates
        if hasattr(self, 'last_counters'):
            elapsed = self.refresh_rate
            for i in range(self.max_buckets):
                current = current_counters.get(i, 0)
                last = self.last_counters.get(i, 0)
                rate = (current - last) / elapsed
                self.packet_rates[i] = rate

        self.last_counters = current_counters.copy()
        self.current_data = current_counters

        # Update history
        total_packets = sum(current_counters.values())
        self.total_packets_history.append(total_packets)

    def run(self):
        """Run the TUI"""
        # Find map
        if not self.find_map_id('bucket_counters'):
            self.console.print("[red]Error: Could not find bucket_counters map[/red]")
            self.console.print("Make sure the XDP program is loaded:")
            self.console.print(f"  sudo-rs ip link set dev {self.interface} xdpgeneric obj xdp_rss_simple.o sec xdp")
            return

        # Create layout
        layout = self.create_layout()

        # Start live display
        with Live(layout, refresh_per_second=1/self.refresh_rate, console=self.console) as live:
            while self.running:
                self.update_data()
                live.update(layout)
                time.sleep(self.refresh_rate)

        # Cleanup message
        self.console.print("\n[yellow]RSS Monitor stopped. Thank you! 🚀[/yellow]")

def main():
    parser = argparse.ArgumentParser(description='Beautiful RSS TUI Monitor')
    parser.add_argument('-i', '--interface', default='lo', help='Interface (default: lo)')
    parser.add_argument('-b', '--buckets', type=int, default=8, help='Buckets (default: 8)')
    parser.add_argument('-r', '--refresh', type=float, default=1.0, help='Refresh rate (default: 1.0s)')

    args = parser.parse_args()

    tui = RSSTUI(
        interface=args.interface,
        max_buckets=args.buckets,
        refresh_rate=args.refresh
    )
    tui.run()

if __name__ == '__main__':
    main()