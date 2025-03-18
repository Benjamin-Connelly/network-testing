#!/usr/bin/env python3
import sys
import re
import glob
import os
from datetime import datetime
import argparse

def analyze_ping_file(filename):
    """Analyze a ping file and extract key metrics."""
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading file {filename}: {str(e)}", file=sys.stderr)
        return None

    # Extract target information from first line
    target_info = {"ip": "Unknown", "hostname": None}
    ip_match = re.search(r'PING\s+(\S+)(?:\s+\((\S+)\))?', lines[0]) if lines else None
    if ip_match:
        if ip_match.group(2):  # Has both hostname and IP
            target_info["hostname"] = ip_match.group(1)
            target_info["ip"] = ip_match.group(2).strip('()')
        else:
            target_info["ip"] = ip_match.group(1)

    # Check if file has timestamp data (-D option)
    has_timestamps = any(re.search(r'^\[\d+\.\d+\]', line) for line in lines if line.strip())

    # Extract ping times and timestamps
    ping_times = []
    timestamps = []
    sequences = []
    total_pings = 0

    for line in lines:
        # Skip empty lines
        if not line.strip():
            continue

        # Count lines that look like ping attempts (including failures)
        if 'icmp_seq=' in line:
            total_pings += 1

        # Extract timestamp if available
        if has_timestamps:
            ts_match = re.search(r'^\[(\d+\.\d+)\]', line)
            if ts_match:
                timestamps.append(float(ts_match.group(1)))

        # Extract sequence number and ping time (successful pings only)
        seq_match = re.search(r'icmp_seq=(\d+)', line)
        time_match = re.search(r'time=(\d+\.?\d*)', line)

        if seq_match and time_match:
            sequences.append(int(seq_match.group(1)))
            ping_times.append(float(time_match.group(1)))

    # Calculate statistics
    min_time = min(ping_times) if ping_times else 0
    max_time = max(ping_times) if ping_times else 0
    avg_time = sum(ping_times) / len(ping_times) if ping_times else 0
    
    # Calculate mean deviation (mdev)
    mdev = 0
    if ping_times:
        # Calculate mean absolute deviation
        deviations = [abs(t - avg_time) for t in ping_times]
        mdev = sum(deviations) / len(deviations)

    stats = {
        "min": min_time,
        "max": max_time,
        "avg": avg_time,
        "mdev": mdev,
        "total_pings": total_pings,
        "packet_loss": 0
    }

    # Calculate packet loss based on successful pings vs total pings
    if total_pings > 0:
        stats["packet_loss"] = ((total_pings - len(ping_times)) / total_pings) * 100

    # Calculate time range if timestamps available
    time_range = None
    if timestamps:
        start_time = datetime.fromtimestamp(min(timestamps))
        end_time = datetime.fromtimestamp(max(timestamps))
        time_range = (start_time, end_time)

    return {
        "target": target_info,
        "stats": stats,
        "time_range": time_range,
        "has_timestamps": has_timestamps
    }

def generate_markdown(results):
    """Generate markdown output from analysis results."""
    markdown = []

    for filename, data in results.items():
        if not data:
            continue

        # Add header with filename
        markdown.append(f"## Ping Analysis: {os.path.basename(filename)}")
        markdown.append("")

        # Add target information
        target = data["target"]
        if target["hostname"]:
            markdown.append(f"**Host:** {target['hostname']} ({target['ip']})")
        else:
            markdown.append(f"**Host:** {target['ip']}")
        markdown.append("")

        # Add time range if available
        if data["time_range"]:
            start, end = data["time_range"]
            markdown.append(f"**Time Range:** {start.strftime('%Y-%m-%d %H:%M:%S')} to {end.strftime('%Y-%m-%d %H:%M:%S')}")
            markdown.append("")

        # Add statistics table
        markdown.append("| Metric | Value |")
        markdown.append("|--------|-------|")
        markdown.append(f"| Minimum Latency | {data['stats']['min']:.1f} ms |")
        markdown.append(f"| Average Latency | {data['stats']['avg']:.1f} ms |")
        markdown.append(f"| Maximum Latency | {data['stats']['max']:.1f} ms |")
        markdown.append(f"| Mean Deviation | {data['stats']['mdev']:.1f} ms |")
        markdown.append(f"| Packet Loss | {data['stats']['packet_loss']:.1f}% |")
        markdown.append(f"| Total Pings | {data['stats']['total_pings']} |")
        markdown.append("")
        markdown.append("")

    return "\n".join(markdown)

def is_ping_file(filename):
    """Check if a file is a ping file by reading its first 10 lines."""
    try:
        with open(filename, 'r') as f:
            # Read first 10 lines
            head = ''.join([next(f, '') for _ in range(10)]).lower()
            return 'ping' in head
    except Exception as e:
        print(f"Error reading file {filename}: {str(e)}", file=sys.stderr)
        return False

def main():
    """Main function to process ping files and generate markdown output."""
    # Get files from command line arguments or use default pattern
    if len(sys.argv) > 1:
        files = []
        for arg in sys.argv[1:]:
            if os.path.isdir(arg):
                # If argument is a directory, search for .txt and .log files within it
                for pattern in ["*.txt", "*.log"]:
                    matched_files = glob.glob(os.path.join(arg, "**", pattern), recursive=True)
                    # Filter files that contain "ping" in first 10 lines
                    ping_files = [f for f in matched_files if is_ping_file(f)]
                    files.extend(ping_files)
                if not files:
                    print(f"Warning: No ping files found in directory '{arg}'", file=sys.stderr)
            else:
                # If argument is a file pattern
                matched_files = glob.glob(arg)
                if matched_files:
                    # Filter files that contain "ping" in first 10 lines
                    ping_files = [f for f in matched_files if f.endswith(('.txt', '.log')) and is_ping_file(f)]
                    files.extend(ping_files)
                else:
                    print(f"Warning: No files found matching pattern '{arg}'", file=sys.stderr)
    else:
        # Default to all .txt and .log files in current directory
        patterns = ["*.txt", "*.log"]
        files = []
        for pattern in patterns:
            matched_files = glob.glob(pattern)
            # Filter files that contain "ping" in first 10 lines
            ping_files = [f for f in matched_files if is_ping_file(f)]
            files.extend(ping_files)

    if not files:
        print("Error: No ping files found to analyze.", file=sys.stderr)
        sys.exit(1)

    # Analyze each file
    results = {}
    for file in files:
        result = analyze_ping_file(file)
        if result:
            results[file] = result

    # Generate and print markdown
    if results:
        print(generate_markdown(results))
    else:
        print("No valid ping data found in input files.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()