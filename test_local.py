#!/usr/bin/env python3
"""
Test script for UDP Discovery Tool
Run this against the Docker test environment
"""

import subprocess
import sys
import json
from colorama import init, Fore, Style

init(autoreset=True)

def run_test(target, ports, description):
    """Run a test scan"""
    print(f"\n{Fore.CYAN}[TEST] {description}{Style.RESET_ALL}")
    print(f"Target: {target}, Ports: {ports}")

    cmd = [
        'python3', 'udp_discovery.py',
        '-t', target,
        '-p', ports,
        '--timeout', '3',
        '--output', 'json'
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            # Try to parse JSON output
            lines = result.stdout.strip().split('\n')
            # Find the JSON part (skip status messages)
            json_start = -1
            for i, line in enumerate(lines):
                if line.strip().startswith('[') or line.strip().startswith('{'):
                    json_start = i
                    break

            if json_start >= 0:
                json_output = '\n'.join(lines[json_start:])
                try:
                    results = json.loads(json_output)
                    print(f"{Fore.GREEN}✓ Found {len(results)} services{Style.RESET_ALL}")
                    for service in results:
                        print(f"  - {service['target']}:{service['port']} - {service.get('service', 'Unknown')}")
                except json.JSONDecodeError:
                    print(f"{Fore.YELLOW}⚠ Could not parse JSON output{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}⚠ No services found{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}✗ Command failed with exit code {result.returncode}{Style.RESET_ALL}")
            if result.stderr:
                print(f"Error: {result.stderr}")

    except subprocess.TimeoutExpired:
        print(f"{Fore.RED}✗ Test timed out{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}✗ Test failed: {e}{Style.RESET_ALL}")

def main():
    print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}UDP Discovery Tool - Local Testing{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")

    # Check if Docker services are running
    print(f"\n{Fore.YELLOW}[*] Make sure Docker services are running:{Style.RESET_ALL}")
    print("    docker compose up -d")

    # Test cases
    tests = [
        ('localhost', '5353', 'DNS Service (port 5353)'),
        ('localhost', '1161', 'SNMP Service (port 1161)'),
        ('localhost', '1123', 'NTP Service (port 1123)'),
        ('localhost', '1069', 'TFTP Service (port 1069)'),
        ('localhost', '1007,1009,1013,1019', 'Legacy Services (echo, discard, daytime, chargen)'),
        ('localhost', '1137', 'NetBIOS Name Service (port 1137)'),
        ('localhost', 'common', 'Common UDP ports scan'),
    ]

    for target, ports, description in tests:
        run_test(target, ports, description)

    print(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] Testing complete!{Style.RESET_ALL}")

    # Manual test suggestion
    print(f"\n{Fore.YELLOW}[*] For manual testing, try:{Style.RESET_ALL}")
    print("    sudo python3 udp_discovery.py -t localhost -p 1-65535 --timeout 2")

if __name__ == '__main__':
    main()