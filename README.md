# Network Scanner

A Python script that scans your local network ARP table and identifies device manufacturers using MAC address lookups.

## Features

- 🔍 **Local ARP Scanning** - Reads your system's ARP table to find connected devices
- 🏭 **Manufacturer Lookup** - Identifies device manufacturers using MAC addresses
- ⚡ **Fast Local Database** - Built-in OUI database for 289+ manufacturers (Apple, Microsoft, NETGEAR, etc.)
- 🌐 **API Fallback** - Uses MacVendors.com API for unknown devices with rate limiting
- 📊 **Multiple Formats** - Output as table, JSON, or CSV
- 💾 **Save Results** - Export scan results to file

## Quick Start

```bash
# Install dependencies
pip install requests tabulate

# Basic scan
python network_scanner.py

# Fast scan (no API lookups)
python network_scanner.py --no-lookup

# Save results
python network_scanner.py --save network_scan.json
```

## Example Output

```
Network Scan Results (4 devices found):
╒═══════════════╤═══════════════════╤═══════════════════════╕
│ IP Address    │ MAC Address       │ Manufacturer          │
╞═══════════════╪═══════════════════╪═══════════════════════╡
│ 192.168.1.1   │ AC:DE:48:11:22:33 │ Apple                 │
│ 192.168.1.100 │ 00:50:56:44:55:66 │ VMware                │
│ 192.168.1.150 │ 00:26:F2:77:88:99 │ NETGEAR               │
│ 192.168.1.200 │ B8:27:EB:AA:BB:CC │ Raspberry Pi Foundation│
╘═══════════════╧═══════════════════╧═══════════════════════╛
```

## Requirements

- **Python 3.8+**
- **macOS/Linux** (Windows may need modifications)
- **Network connection** for API lookups

## Command Options

- `--format {table,json,csv}` - Output format
- `--save FILENAME` - Save to file
- `--no-lookup` - Skip manufacturer lookup (faster)
- `--help` - Show all options

Perfect for network admins, security professionals, or anyone curious about devices on their network!
