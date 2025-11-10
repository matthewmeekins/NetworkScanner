#!/usr/bin/env python3
"""
Network ARP Scanner with MAC Address Manufacturer Lookup
Scans the local network, gets MAC addresses, and identifies device manufacturers.
"""

import argparse
import sys
import time
import json
import subprocess
import re
import requests
from tabulate import tabulate


class NetworkScanner:
    """
    Network ARP Scanner with MAC Address Manufacturer Lookup.
    
    Scans the local network ARP table and identifies device manufacturers
    using a local OUI database with API fallback for unknown devices.
    """
    def __init__(self):
        self.arp_table = []
        self.mac_vendor_api = "https://api.macvendors.com/"
        self.rate_limit_delay = 1.1  # Delay between API calls (seconds)
        self.oui_database = self._load_oui_database()

    def _load_oui_database(self):
        """Load a basic OUI database for common manufacturers"""
        return {
            # Apple
            "00:03:93": "Apple",
            "00:05:02": "Apple",
            "00:0A:27": "Apple",
            "00:0A:95": "Apple",
            "00:0D:93": "Apple",
            "00:11:24": "Apple",
            "00:14:51": "Apple",
            "00:16:CB": "Apple",
            "00:17:F2": "Apple",
            "00:19:E3": "Apple",
            "00:1B:63": "Apple",
            "00:1E:C2": "Apple",
            "00:21:E9": "Apple",
            "00:22:41": "Apple",
            "00:23:12": "Apple",
            "00:23:32": "Apple",
            "00:23:6C": "Apple",
            "00:23:DF": "Apple",
            "00:24:36": "Apple",
            "00:25:00": "Apple",
            "00:25:4B": "Apple",
            "00:25:BC": "Apple",
            "00:26:08": "Apple",
            "00:26:4A": "Apple",
            "00:26:B0": "Apple",
            "00:26:BB": "Apple",
            "04:0C:CE": "Apple",
            "04:15:52": "Apple",
            "04:1E:64": "Apple",
            "04:26:65": "Apple",
            "04:4F:AA": "Apple",
            "04:54:53": "Apple",
            "04:69:F8": "Apple",
            "04:98:F3": "Apple",
            "04:DB:56": "Apple",
            "04:E5:36": "Apple",
            "04:F1:3E": "Apple",
            "04:F7:E4": "Apple",
            "08:74:02": "Apple",
            "0C:30:21": "Apple",
            "0C:4D:E9": "Apple",
            "0C:77:1A": "Apple",
            "10:40:F3": "Apple",
            "14:10:9F": "Apple",
            "14:5A:05": "Apple",
            "14:7D:DA": "Apple",
            "14:BD:61": "Apple",
            "18:34:51": "Apple",
            "18:65:90": "Apple",
            "18:AF:61": "Apple",
            "1C:1A:C0": "Apple",
            "1C:36:BB": "Apple",
            "1C:AB:A7": "Apple",
            "20:78:F0": "Apple",
            "20:AB:37": "Apple",
            "24:18:1D": "Apple",
            "24:A0:74": "Apple",
            "24:AB:81": "Apple",
            "28:37:37": "Apple",
            "28:6A:BA": "Apple",
            "28:6A:B8": "Apple",
            "28:CF:DA": "Apple",
            "2C:BE:08": "Apple",
            "2C:F0:A2": "Apple",
            "2C:F0:EE": "Apple",
            "30:10:B3": "Apple",
            "30:90:AB": "Apple",
            "30:F7:C5": "Apple",
            "34:15:9E": "Apple",
            "34:36:3B": "Apple",
            "34:A3:95": "Apple",
            "38:0B:40": "Apple",
            "3C:07:54": "Apple",
            "3C:15:C2": "Apple",
            "3C:2E:F9": "Apple",
            "40:B3:95": "Apple",
            "40:CB:C0": "Apple",
            "44:2A:60": "Apple",
            "44:4C:0C": "Apple",
            "44:D8:84": "Apple",
            "48:74:6E": "Apple",
            "4C:8D:79": "Apple",
            "4C:B1:99": "Apple",
            "50:32:37": "Apple",
            "50:82:D5": "Apple",
            "54:26:96": "Apple",
            "54:72:4F": "Apple",
            "54:AE:27": "Apple",
            "54:E4:3A": "Apple",
            "58:55:CA": "Apple",
            "5C:59:48": "Apple",
            "5C:F9:38": "Apple",
            "60:33:4B": "Apple",
            "60:C5:47": "Apple",
            "60:FB:42": "Apple",
            "64:12:25": "Apple",
            "64:20:9F": "Apple",
            "64:B9:E8": "Apple",
            "64:E6:82": "Apple",
            "68:96:7B": "Apple",
            "68:D9:3C": "Apple",
            "6C:19:8F": "Apple",
            "6C:40:08": "Apple",
            "6C:8D:C1": "Apple",
            "70:11:24": "Apple",
            "70:73:CB": "Apple",
            "70:CD:60": "Apple",
            "74:E2:E6": "Apple",
            "78:31:C1": "Apple",
            "78:4F:43": "Apple",
            "78:7B:8A": "Apple",
            "7C:6D:62": "Apple",
            "7C:C3:A1": "Apple",
            "7C:C7:09": "Apple",
            "80:92:9F": "Apple",
            "80:BE:05": "Apple",
            "80:E6:50": "Apple",
            "84:38:35": "Apple",
            "84:85:06": "Apple",
            "84:FC:FE": "Apple",
            "88:1F:A1": "Apple",
            "88:53:95": "Apple",
            "88:63:DF": "Apple",
            "8C:58:77": "Apple",
            "8C:7C:92": "Apple",
            "90:84:0D": "Apple",
            "90:FD:61": "Apple",
            "94:E9:6A": "Apple",
            "98:03:D8": "Apple",
            "98:B8:E3": "Apple",
            "9C:04:EB": "Apple",
            "9C:84:BF": "Apple",
            "A0:99:9B": "Apple",
            "A4:5E:60": "Apple",
            "A4:83:E7": "Apple",
            "A4:B1:97": "Apple",
            "A8:20:66": "Apple",
            "A8:51:AB": "Apple",
            "A8:88:08": "Apple",
            "A8:96:8A": "Apple",
            "AC:87:A3": "Apple",
            "AC:BC:32": "Apple",
            "AC:DE:48": "Apple",
            "B0:65:BD": "Apple",
            "B4:F0:AB": "Apple",
            "B8:09:8A": "Apple",
            "B8:17:C2": "Apple",
            "B8:53:AC": "Apple",
            "B8:C7:5D": "Apple",
            "B8:E8:56": "Apple",
            "BC:52:B7": "Apple",
            "BC:67:1C": "Apple",
            "BC:93:5E": "Apple",
            "C0:84:7A": "Apple",
            "C4:2C:03": "Apple",
            "C8:2A:14": "Apple",
            "C8:33:4B": "Apple",
            "C8:B5:B7": "Apple",
            "CC:08:8D": "Apple",
            "CC:25:EF": "Apple",
            "D0:23:DB": "Apple",
            "D0:81:7A": "Apple",
            "D4:85:64": "Apple",
            "D4:9A:20": "Apple",
            "D8:30:62": "Apple",
            "D8:96:95": "Apple",
            "D8:A2:5E": "Apple",
            "DC:2B:2A": "Apple",
            "DC:37:45": "Apple",
            "DC:56:E7": "Apple",
            "DC:A4:CA": "Apple",
            "E0:AC:CB": "Apple",
            "E4:25:E7": "Apple",
            "E8:8D:28": "Apple",
            "EC:35:86": "Apple",
            "F0:18:98": "Apple",
            "F0:2F:74": "Apple",
            "F0:B4:79": "Apple",
            "F4:0F:24": "Apple",
            "F4:31:C3": "Apple",
            "F4:5C:89": "Apple",
            "F8:1E:DF": "Apple",
            "F8:4F:AD": "Apple",
            "FC:25:3F": "Apple",
            "FC:E9:98": "Apple",
            # Microsoft
            "00:03:FF": "Microsoft",
            "00:12:F0": "Microsoft",
            "00:15:5D": "Microsoft",
            "00:17:FA": "Microsoft",
            "00:1D:D8": "Microsoft",
            "00:50:F2": "Microsoft",
            "7C:1E:52": "Microsoft",
            "00:0D:3A": "Microsoft",
            # NETGEAR
            "00:09:5B": "NETGEAR",
            "00:0F:B5": "NETGEAR",
            "00:14:6C": "NETGEAR",
            "00:1B:2F": "NETGEAR",
            "00:1E:2A": "NETGEAR",
            "00:22:3F": "NETGEAR",
            "00:24:B2": "NETGEAR",
            "00:26:F2": "NETGEAR",
            "20:4E:7F": "NETGEAR",
            "28:C6:8E": "NETGEAR",
            "2C:30:33": "NETGEAR",
            "30:46:9A": "NETGEAR",
            "A0:04:60": "NETGEAR",
            "A4:2B:8C": "NETGEAR",
            "B0:7F:B9": "NETGEAR",
            "C0:3F:0E": "NETGEAR",
            "C4:04:15": "NETGEAR",
            "E0:46:9A": "NETGEAR",
            "E4:F4:C6": "NETGEAR",
            # VMware/Virtual machines
            "00:50:56": "VMware",
            "00:0C:29": "VMware",
            "00:05:69": "VMware",
            "00:1C:14": "VMware",
            "08:00:27": "Oracle VirtualBox",
            "52:54:00": "QEMU/KVM",
            "00:16:3E": "Xen",
            # Cisco
            "00:01:42": "Cisco",
            "00:01:43": "Cisco",
            "00:01:64": "Cisco",
            "00:01:96": "Cisco",
            "00:01:97": "Cisco",
            "00:01:C7": "Cisco",
            "00:01:C9": "Cisco",
            "00:02:16": "Cisco",
            "00:02:17": "Cisco",
            "00:02:4A": "Cisco",
            "00:02:4B": "Cisco",
            "00:02:B9": "Cisco",
            "00:02:BA": "Cisco",
            "00:02:FC": "Cisco",
            "00:02:FD": "Cisco",
            # Linksys
            "00:06:25": "Linksys",
            "00:0C:41": "Linksys",
            "00:0E:08": "Linksys",
            "00:12:17": "Linksys",
            "00:13:10": "Linksys",
            "00:14:BF": "Linksys",
            "00:16:B6": "Linksys",
            "00:18:39": "Linksys",
            "00:18:F8": "Linksys",
            "00:1A:70": "Linksys",
            "00:1C:10": "Linksys",
            "00:1D:7E": "Linksys",
            # D-Link
            "00:05:5D": "D-Link",
            "00:0F:3D": "D-Link",
            "00:11:95": "D-Link",
            "00:13:46": "D-Link",
            "00:15:E9": "D-Link",
            "00:17:9A": "D-Link",
            "00:19:5B": "D-Link",
            "00:1B:11": "D-Link",
            "00:1C:F0": "D-Link",
            "00:1E:58": "D-Link",
            "00:21:91": "D-Link",
            "00:22:B0": "D-Link",
            # TP-Link
            "00:27:19": "TP-Link",
            "14:CC:20": "TP-Link",
            "50:C7:BF": "TP-Link",
            "64:70:02": "TP-Link",
            "A4:2B:B0": "TP-Link",
            "C4:6E:1F": "TP-Link",
            "E8:DE:27": "TP-Link",
            "F4:EC:38": "TP-Link",
            # Samsung
            "00:07:AB": "Samsung",
            "00:12:FB": "Samsung",
            "00:15:99": "Samsung",
            "00:16:6B": "Samsung",
            "00:16:6C": "Samsung",
            "00:17:C9": "Samsung",
            "00:17:D5": "Samsung",
            "00:18:AF": "Samsung",
            "00:1A:8A": "Samsung",
            "00:1B:98": "Samsung",
            "00:1D:25": "Samsung",
            "00:1E:7D": "Samsung",
            "00:21:19": "Samsung",
            "00:23:39": "Samsung",
            "00:24:54": "Samsung",
            # LG
            "00:1C:62": "LG",
            "00:1E:75": "LG",
            "00:22:A9": "LG",
            "00:26:E2": "LG",
            "10:F1:F2": "LG",
            "64:E5:99": "LG",
            "B4:07:F9": "LG",
            "CC:2D:E0": "LG",
        }

    def _lookup_oui_local(self, mac_address):
        """Look up manufacturer using local OUI database"""
        # Extract first 3 octets (OUI) from MAC address
        mac = mac_address.replace(":", "").replace("-", "").upper()
        oui = mac[:6]
        oui_formatted = ":".join([oui[i : i + 2] for i in range(0, 6, 2)])

        return self.oui_database.get(oui_formatted, None)

    def get_arp_table(self):
        """Get ARP table from system using arp -a command"""
        try:
            result = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, check=True
            )
            entries = []

            for line in result.stdout.split("\n"):
                # Parse ARP output: hostname (IP) at MAC [ether] on interface
                # Example: router.local (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on en0
                match = re.search(r"\(([\d.]+)\) at ([a-fA-F0-9:]+)", line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2).upper()
                    # Skip incomplete entries (00:00:00:00:00:00 or incomplete MACs)
                    if mac != "00:00:00:00:00:00" and len(mac.replace(":", "")) == 12:
                        entries.append(
                            {"ip": ip, "mac": mac, "manufacturer": "Unknown"}
                        )

            self.arp_table = entries
            return entries

        except subprocess.CalledProcessError as e:
            print(f"Error running arp command: {e}")
            return []
        except (OSError, ValueError) as e:
            print(f"Error parsing ARP table: {e}")
            return []

    def lookup_manufacturer(self, mac_address):
        """Lookup manufacturer for a given MAC address using local DB first, then API"""
        # First try local OUI database
        local_result = self._lookup_oui_local(mac_address)
        if local_result:
            return local_result

        # If not found locally, try API with rate limiting
        print(f"  API lookup for {mac_address[:8]}...", end=" ")
        time.sleep(self.rate_limit_delay)  # Rate limiting

        try:
            # Clean MAC address format
            mac = mac_address.replace(":", "").replace("-", "").upper()
            mac_formatted = ":".join([mac[i : i + 2] for i in range(0, 12, 2)])

            response = requests.get(f"{self.mac_vendor_api}{mac_formatted}", timeout=5)

            if response.status_code == 200:
                result = response.text.strip()
                print("✓")
                return result
            if response.status_code == 404:
                print("✗ Not found")
                return "Unknown Manufacturer"
            if response.status_code == 429:
                print("✗ Rate limited")
                return "Rate Limited - Try Again Later"

            print(f"✗ Error {response.status_code}")
            return f"API Error ({response.status_code})"

        except requests.exceptions.Timeout:
            print("✗ Timeout")
            return "Lookup Timeout"
        except requests.exceptions.RequestException as e:
            print("✗ Network error")
            return f"Network Error: {str(e)[:30]}..."
        except (ValueError, KeyError) as e:
            print("✗ Error")
            return f"Error: {str(e)[:30]}..."

    def get_manufacturers(self):
        """Get manufacturers for all MAC addresses in ARP table"""
        print("Looking up manufacturers...")
        local_count = 0
        api_count = 0

        for i, entry in enumerate(self.arp_table):
            print(f"\nProgress: {i+1}/{len(self.arp_table)} - {entry['mac']}")

            # Check if we can resolve locally first
            local_result = self._lookup_oui_local(entry["mac"])
            if local_result:
                entry["manufacturer"] = local_result
                local_count += 1
                print(f"  Local DB: {local_result}")
            else:
                entry["manufacturer"] = self.lookup_manufacturer(entry["mac"])
                api_count += 1

        print("\n✅ Lookup complete!")
        print(f"   Local DB hits: {local_count}")
        print(f"   API calls made: {api_count}")

    def display_results(self, format_type="table"):
        """Display results in specified format"""
        if not self.arp_table:
            print("No ARP entries found.")
            return

        if format_type == "table":
            headers = ["IP Address", "MAC Address", "Manufacturer"]
            table_data = [
                [entry["ip"], entry["mac"], entry["manufacturer"]]
                for entry in self.arp_table
            ]
            print(f"\nNetwork Scan Results ({len(self.arp_table)} devices found):")
            print("=" * 60)
            print(tabulate(table_data, headers=headers, tablefmt="grid"))

        elif format_type == "json":
            print(json.dumps(self.arp_table, indent=2))

        elif format_type == "csv":
            print("IP Address,MAC Address,Manufacturer")
            for entry in self.arp_table:
                print(f"{entry['ip']},{entry['mac']},{entry['manufacturer']}")

    def save_results(self, filename, format_type="json"):
        """Save results to file"""
        try:
            with open(filename, "w", encoding="utf-8") as f:
                if format_type == "json":
                    json.dump(self.arp_table, f, indent=2)
                elif format_type == "csv":
                    f.write("IP Address,MAC Address,Manufacturer\n")
                    for entry in self.arp_table:
                        f.write(
                            f"{entry['ip']},{entry['mac']},{entry['manufacturer']}\n"
                        )
            print(f"Results saved to {filename}")
        except (OSError, IOError) as e:
            print(f"Error saving file: {e}")


def main():
    """
    Main function to handle command line arguments and execute the network scan.
    """
    parser = argparse.ArgumentParser(
        description="Network ARP Scanner with Manufacturer Lookup"
    )
    parser.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    parser.add_argument("--save", help="Save results to file")
    parser.add_argument(
        "--save-format",
        choices=["json", "csv"],
        default="json",
        help="File save format (default: json)",
    )
    parser.add_argument(
        "--no-lookup", action="store_true", help="Skip manufacturer lookup (faster)"
    )

    args = parser.parse_args()

    # Create scanner instance
    scanner = NetworkScanner()

    # Get ARP table
    print("Scanning local ARP table...")
    entries = scanner.get_arp_table()

    if not entries:
        print("No devices found in ARP table.")
        print("Try: ping -c 1 192.168.1.1 (or your gateway) to populate ARP table")
        sys.exit(1)

    print(f"Found {len(entries)} devices in ARP table.")

    # Get manufacturers unless skipped
    if not args.no_lookup:
        scanner.get_manufacturers()

    # Display results
    scanner.display_results(args.format)

    # Save if requested
    if args.save:
        scanner.save_results(args.save, args.save_format)


if __name__ == "__main__":
    main()
