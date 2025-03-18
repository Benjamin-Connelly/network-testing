# Network Ping Analysis Tool

A simple command-line tool for analyzing ping log files to detect network issues such as packet loss and latency patterns.

## Features

- Analyzes ping log files to extract key metrics
- Generates markdown output with statistics
- Supports analyzing multiple files at once
- Detects packet loss and latency patterns

## Usage

### Analyzing Log Files

```bash
python ping-tool.py <file_or_directory1> [<file_or_directory2> ...]
```

You can provide either files or directories as arguments:
- For files: The tool will analyze each specified ping log file
- For directories: The tool will search for files matching `*.txt` or `*.log` and check their contents for ping data

If no arguments are specified, the tool will look for matching files in the current directory.

## Output Format

The tool generates markdown output with the following information for each analyzed file:

- Target hostname and IP address
- Time range of the ping data (if timestamps are present)
- Key statistics:
  - Minimum latency
  - Average latency
  - Maximum latency
  - Mean deviation (mdev)
  - Packet loss percentage
  - Total number of pings

## Requirements

- Python 3.6+
- No additional packages required

## Installation

1. Clone the repository
2. The script can be run directly with Python 3.6 or higher

## License

This project is licensed under the MIT License - see the LICENSE file for details.