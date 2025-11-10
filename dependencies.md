# Dependencies for network_scanner.py

## Python Requirements

**Minimum Python Version:** 3.8+

## Required Python Packages

### Production Dependencies

| Package | Version | Purpose | Installation |
|---------|---------|---------|--------------|
| `requests` | Latest | HTTP requests for MAC vendor API lookup | `pip install requests` |
| `tabulate` | Latest | Format output tables for display | `pip install tabulate` |

### Standard Library Dependencies
These are included with Python and require no installation:

| Module | Purpose |
|--------|---------|
| `argparse` | Command line argument parsing |
| `subprocess` | Execute system commands (arp -a) |
| `re` | Regular expressions for parsing ARP output |
| `json` | JSON file output format |
| `sys` | System operations and exit codes |
| `time` | Rate limiting delays |

## System Dependencies

### Required System Commands
| Command | Purpose | Availability |
|---------|---------|--------------|
| `arp` | Query ARP table for network devices | Built into macOS/Linux |

### Network Requirements
- **Internet Connection**: Required for MAC vendor API lookups (fallback when local OUI database doesn't have manufacturer)
- **Network Access**: Must be connected to a network with other devices for meaningful results

## Installation Instructions

### Quick Setup
```bash
# Install required packages
pip install requests tabulate

# Or install from requirements.txt
pip install -r requirements.txt
```

### Virtual Environment Setup (Recommended)
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install requests tabulate

# Save current dependencies
pip freeze > requirements.txt
```

## Optional Enhancements

### Development Dependencies
```bash
# Code quality tools (optional)
pip install pylint black

# Testing (optional)
pip install pytest
```

### Alternative Installation Methods
```bash
# Using conda
conda install requests
conda install -c conda-forge tabulate

# Using poetry
poetry add requests tabulate
```

## API Dependencies

### MAC Vendor Lookup Service
- **Service**: MacVendors.com API
- **URL**: `https://api.macvendors.com/`
- **Rate Limit**: ~1 request per second (handled automatically by script)
- **Fallback**: Local OUI database with 289+ manufacturers
- **Cost**: Free for reasonable usage

## Compatibility

### Operating Systems
| OS | Support | Notes |
|----|---------|-------|
| macOS | ✅ Full | Primary development platform |
| Linux | ✅ Full | Standard `arp` command available |
| Windows | ⚠️ Partial | May need `arp -a` command format adjustment |

### Python Versions
| Version | Support | Notes |
|---------|---------|-------|
| Python 3.14+ | ✅ Tested | Current development version |
| Python 3.8-3.13 | ✅ Expected | Should work with f-strings and modern features |
| Python 3.7 | ⚠️ May work | Not tested, f-strings required |
| Python 2.x | ❌ Not supported | Uses Python 3+ features |

## Troubleshooting Dependencies

### Common Issues

**ImportError: No module named 'requests'**
```bash
pip install requests
```

**ImportError: No module named 'tabulate'**
```bash
pip install tabulate
```

**Command 'arp' not found**
- macOS/Linux: `arp` should be built-in
- Windows: Use `arp -a` (may need script modification)

**API Rate Limiting (429 errors)**
- Script includes automatic rate limiting (1.1s delays)
- Local OUI database reduces API calls by ~70-80%
- Rate limits reset after time period

### Network Issues
**No devices found in ARP table**
```bash
# Populate ARP table by pinging gateway
ping -c 1 192.168.1.1  # Replace with your gateway IP
```

**API timeout errors**
- Check internet connection
- API may be temporarily unavailable
- Local OUI database will still provide results for known manufacturers

## Performance Notes

- **Local OUI Database**: 289 manufacturers, instant lookup
- **API Fallback**: ~1 second per unknown device (rate limited)
- **Typical Performance**: 5-10 devices scan in 2-5 seconds
- **Large Networks**: Primarily limited by API rate limiting for unknown devices

## Security Considerations

- Script only reads local ARP table (no network scanning)
- Makes HTTPS requests to MacVendors.com API
- No sensitive data stored or transmitted
- No elevated privileges required