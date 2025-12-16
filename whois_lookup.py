#!/usr/bin/env python3
"""
Extract IP addresses from CSV files and perform whois lookups.
"""

import csv
import re
import ipaddress
import subprocess
import sys
import glob
import os
from collections import OrderedDict

def is_public_ip(ip_str):
    """Check if an IP address is public (not private, multicast, or special)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        # Exclude private, multicast, link-local, loopback, and reserved addresses
        return (
            ip.is_global and 
            not ip.is_multicast and 
            not ip.is_link_local and 
            not ip.is_loopback and 
            not ip.is_reserved
        )
    except ValueError:
        return False

def extract_ips_from_flow(flow_str):
    """Extract IP addresses from flow string like '10.31.3.23->17.248.185.39 (UDP)'."""
    # Match IP addresses in the flow string
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, flow_str)
    return ips

def get_whois_info(ip):
    """Perform whois lookup for an IP address."""
    try:
        result = subprocess.run(
            ['whois', ip],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Error: whois lookup timed out"
    except FileNotFoundError:
        return "Error: whois command not found. Please install whois."
    except Exception as e:
        return f"Error: {str(e)}"

def process_csv_file(file_path, all_ips):
    """Process a single CSV file and extract IP addresses."""
    print(f"Reading CSV file: {file_path}")
    try:
        with open(file_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                flow = row.get('flow', '')
                ips = extract_ips_from_flow(flow)
                all_ips.update(ips)
    except csv.Error as e:
        print(f"Error parsing CSV {file_path}: {str(e)}")
    except Exception as e:
        print(f"Error reading {file_path}: {str(e)}")

def main():
    data_dir = 'data'
    
    # Find all .csv files in the data directory
    csv_pattern = os.path.join(data_dir, '*.csv')
    csv_files = glob.glob(csv_pattern)
    
    if not csv_files:
        print(f"No .csv files found in {data_dir}/ directory")
        return
    
    print(f"Found {len(csv_files)} CSV file(s) to process")
    
    # Collect all unique IP addresses from all CSV files
    all_ips = set()
    
    for csv_file in sorted(csv_files):
        process_csv_file(csv_file, all_ips)
    
    print(f"\nFound {len(all_ips)} unique IP addresses")
    
    # Separate public and private IPs
    public_ips = []
    private_ips = []
    
    for ip in sorted(all_ips):
        if is_public_ip(ip):
            public_ips.append(ip)
        else:
            private_ips.append(ip)
    
    print(f"Public IPs: {len(public_ips)}")
    print(f"Private/Special IPs: {len(private_ips)}")
    
    if private_ips:
        print(f"\nPrivate/Special IPs (skipping whois): {', '.join(private_ips)}")
    
    # Perform whois lookups for public IPs
    print(f"\n{'='*80}")
    print("WHOIS LOOKUPS FOR PUBLIC IP ADDRESSES")
    print(f"{'='*80}\n")
    
    for ip in public_ips:
        print(f"\n{'='*80}")
        print(f"IP Address: {ip}")
        print(f"{'='*80}")
        whois_output = get_whois_info(ip)
        print(whois_output)
        print()

if __name__ == '__main__':
    main()

