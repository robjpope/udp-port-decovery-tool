#!/usr/bin/env python3
"""
Test script for UDP Discovery Tool - Internal Docker Network
Run this inside the scanner container
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
            # Try to parse JSON output from the last line (which should be JSON)
            lines = result.stdout.strip().split('\n')
            json_found = False

            # Look for JSON starting from the end of output
            for i in range(len(lines) - 1, -1, -1):
                line = lines[i].strip()
                if line.startswith('[') or line.startswith('{'):
                    try:
                        # Try to parse as JSON
                        if line.startswith('['):
                            # Array format
                            json_data = line
                        else:
                            # Try to collect complete JSON object
                            json_lines = []
                            brace_count = 0
                            for j in range(i, len(lines)):
                                json_lines.append(lines[j])
                                brace_count += lines[j].count('{') - lines[j].count('}')
                                if brace_count == 0:
                                    break
                            json_data = '\n'.join(json_lines)

                        results = json.loads(json_data)
                        if isinstance(results, list):
                            print(f"{Fore.GREEN}✓ Found {len(results)} services{Style.RESET_ALL}")
                            for service in results:
                                print(f"  - {service['target']}:{service['port']} - {service.get('service', 'Unknown')}")
                                if 'details' in service and service['details']:
                                    for key, value in service['details'].items():
                                        print(f"    {key}: {value}")
                            json_found = True
                            break
                    except (json.JSONDecodeError, KeyError):
                        continue

            if not json_found:
                # Check if there were any status messages indicating no services found
                if any("Found 0 responsive services" in line for line in lines):
                    print(f"{Fore.YELLOW}⚠ No services found{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}⚠ Could not parse JSON output{Style.RESET_ALL}")
                    print("Raw output:", result.stdout)
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
    print(f"{Fore.CYAN}UDP Discovery Tool - Internal Docker Network Testing{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")

    # Check network connectivity
    print(f"\n{Fore.YELLOW}[*] Testing network connectivity...{Style.RESET_ALL}")

    # Test DNS resolution of service containers
    containers = ['udp-test-dns', 'udp-test-ntp', 'udp-test-tftp', 'udp-test-echo',
                  'udp-test-chargen', 'udp-test-daytime', 'udp-test-time']
    for container in containers:
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '2', container],
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"  ✓ {container} is reachable")
            else:
                print(f"  ✗ {container} is not reachable")
        except:
            print(f"  ✗ {container} - ping failed")

    # Test cases - using container hostnames
    tests = [
        ('udp-test-dns', '53', 'DNS Service (BIND9)'),
        ('udp-test-ntp', '123', 'NTP Service'),
        ('udp-test-tftp', '69', 'TFTP Service'),
        ('udp-test-echo', '7', 'Echo Service'),
        ('udp-test-chargen', '19', 'Character Generator Service'),
        ('udp-test-daytime', '13', 'Daytime Service'),
        ('udp-test-time', '37', 'Time Protocol Service'),
        # Test multiple legacy services
        ('udp-test-chargen', '7,13,19,37', 'Multi-port legacy services scan'),
    ]

    for target, ports, description in tests:
        run_test(target, ports, description)

    print(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[*] Internal network testing complete!{Style.RESET_ALL}")

    # Manual test suggestions
    print(f"\n{Fore.YELLOW}[*] For manual testing inside this container:{Style.RESET_ALL}")
    print("    python3 udp_discovery.py -t udp-test-ntp -p 123")
    print("    python3 udp_discovery.py -t udp-test-tftp -p 69")
    print("    python3 udp_discovery.py -t udp-test-chargen -p 19")
    print("    python3 udp_discovery.py -t udp-test-daytime -p 13")
    print("    python3 udp_discovery.py -t udp-test-time -p 37")
    print("    # Test all legacy services:")
    print("    python3 udp_discovery.py -t 'udp-test-echo,udp-test-chargen,udp-test-daytime,udp-test-time' -p 7,13,19,37")

if __name__ == '__main__':
    main()