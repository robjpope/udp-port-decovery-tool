#!/usr/bin/env python3

import argparse
import asyncio
import json
import sys
import socket
import time
from typing import List, Dict, Any, Optional, Tuple
from colorama import init, Fore, Style
from tabulate import tabulate

from utils.network import parse_ports, validate_target, parse_targets_file, parse_target_spec
from utils.output import OutputFormatter
from probes import PROBE_REGISTRY, get_probe_for_port

init(autoreset=True)

class UDPDiscovery:
    def __init__(self, targets: List[str], ports: List[int], timeout: float = 2.0,
                 retries: int = 1, rate_limit: int = 100, output_format: str = 'text'):
        self.targets = targets
        self.ports = ports
        self.timeout = timeout
        self.retries = retries
        self.rate_limit = rate_limit
        self.output_formatter = OutputFormatter(output_format)
        self.results = []

    async def scan_port(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Scan a single UDP port on target"""
        probe = get_probe_for_port(port)

        if not probe:
            return None

        for attempt in range(self.retries + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)

                probe_data = probe.create_probe()
                sock.sendto(probe_data, (target, port))

                try:
                    response, _ = sock.recvfrom(4096)
                    sock.close()

                    service_info = probe.parse_response(response)

                    return {
                        'target': target,
                        'port': port,
                        'service': probe.name,
                        'status': 'open',
                        'details': service_info,
                        'response_size': len(response)
                    }

                except socket.timeout:
                    sock.close()  # Always close immediately
                    if attempt == self.retries:
                        return {
                            'target': target,
                            'port': port,
                            'service': probe.name,
                            'status': 'filtered',
                            'details': None
                        }
                    # Continue to next retry

                except Exception as e:
                    sock.close()  # Always close immediately
                    if attempt == self.retries:
                        return {
                            'target': target,
                            'port': port,
                            'service': probe.name,
                            'status': 'error',
                            'details': str(e)
                        }
                    # Continue to next retry

            except Exception as e:
                if attempt == self.retries:
                    return {
                        'target': target,
                        'port': port,
                        'service': 'unknown',
                        'status': 'error',
                        'details': str(e)
                    }

        return None

    async def scan_target(self, target: str) -> List[Dict[str, Any]]:
        """Scan all specified ports on a single target"""
        results = []
        semaphore = asyncio.Semaphore(self.rate_limit)

        async def limited_scan(port):
            async with semaphore:
                return await self.scan_port(target, port)

        tasks = [limited_scan(port) for port in self.ports]
        port_results = await asyncio.gather(*tasks)

        for result in port_results:
            if result and result['status'] == 'open':
                results.append(result)

        return results

    async def run(self):
        """Run the UDP discovery scan"""
        # Print status messages to appropriate stream
        output_stream = sys.stdout if self.output_formatter.format == 'text' else sys.stderr

        print(f"{Fore.CYAN}[*] Starting UDP Discovery Scan{Style.RESET_ALL}", file=output_stream)
        print(f"    Targets: {', '.join(self.targets)}", file=output_stream)
        print(f"    Ports: {len(self.ports)} ports", file=output_stream)
        print(f"    Timeout: {self.timeout}s, Retries: {self.retries}", file=output_stream)
        print(file=output_stream)

        start_time = time.time()

        # Scan all targets in parallel
        async def scan_and_report(target):
            print(f"{Fore.YELLOW}[*] Scanning {target}...{Style.RESET_ALL}", file=output_stream)
            target_results = await self.scan_target(target)

            for result in target_results:
                if result['status'] == 'open':
                    print(f"{Fore.GREEN}[+] {target}:{result['port']} - {result['service']}{Style.RESET_ALL}", file=output_stream)
                    if result['details'] and self.output_formatter.format == 'text':
                        for key, value in result['details'].items():
                            print(f"    {key}: {value}", file=output_stream)

            return target_results

        # Create tasks for all targets
        tasks = [scan_and_report(target) for target in self.targets]

        # Run all target scans in parallel
        all_results = await asyncio.gather(*tasks)

        # Flatten results from all targets
        for target_results in all_results:
            self.results.extend(target_results)

        elapsed = time.time() - start_time
        print(file=output_stream)
        print(f"{Fore.CYAN}[*] Scan completed in {elapsed:.2f} seconds{Style.RESET_ALL}", file=output_stream)
        print(f"    Found {len(self.results)} responsive services", file=output_stream)

        return self.results

    def output_results(self):
        """Output results in specified format"""
        if self.output_formatter.format == 'json':
            print(json.dumps(self.results, indent=2))
        elif self.output_formatter.format == 'csv':
            self.output_formatter.to_csv(self.results)
        else:
            if self.results:
                table_data = []
                for r in self.results:
                    details_str = ""
                    if r['details']:
                        details_str = "; ".join([f"{k}={v}" for k, v in r['details'].items()])
                    table_data.append([
                        r['target'],
                        r['port'],
                        r['service'],
                        r['status'],
                        details_str[:50] + '...' if len(details_str) > 50 else details_str
                    ])
                print("\n" + tabulate(table_data,
                                    headers=['Target', 'Port', 'Service', 'Status', 'Details'],
                                    tablefmt='grid'))

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='UDP Port Discovery Tool - Identify services on open UDP ports',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-t', '--target',
                       help='Target IP/hostname/range (e.g., 192.168.1.1, 192.168.1.0/24, 192.168.1.1-10)')
    target_group.add_argument('-f', '--hosts-file',
                       help='File containing targets (nmap-style: IPs, ranges, subnets)')

    parser.add_argument('-p', '--ports', required=True,
                       help='Ports to scan (e.g., 53,161,123 or 1-1000 or "common")')
    parser.add_argument('--timeout', type=float, default=2.0,
                       help='Timeout for each probe in seconds (default: 2.0)')
    parser.add_argument('--retries', type=int, default=1,
                       help='Number of retries for each probe (default: 1)')
    parser.add_argument('--rate-limit', type=int, default=100,
                       help='Maximum concurrent probes (default: 100)')
    parser.add_argument('--output', choices=['text', 'json', 'csv'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')

    return parser.parse_args()

def main():
    args = parse_arguments()

    # Parse targets
    targets = []
    try:
        if args.hosts_file:
            output_stream = sys.stdout if args.output == 'text' else sys.stderr
            print(f"[*] Reading targets from file: {args.hosts_file}", file=output_stream)
            targets = parse_targets_file(args.hosts_file)
            print(f"[*] Loaded {len(targets)} targets from file", file=output_stream)
        else:
            targets = parse_target_spec(args.target)

        if not targets:
            error_msg = f"{Fore.RED}[!] No valid targets found{Style.RESET_ALL}"
            print(error_msg, file=sys.stderr if args.output == 'json' else sys.stdout)
            sys.exit(1)

    except ValueError as e:
        error_msg = f"{Fore.RED}[!] Target parsing error: {e}{Style.RESET_ALL}"
        print(error_msg, file=sys.stderr if args.output == 'json' else sys.stdout)
        sys.exit(1)

    # Validate a sample of targets (to avoid validating thousands)
    sample_targets = targets[:10] if len(targets) > 10 else targets
    for target in sample_targets:
        if not validate_target(target):
            error_msg = f"{Fore.RED}[!] Invalid target: {target}{Style.RESET_ALL}"
            print(error_msg, file=sys.stderr if args.output == 'json' else sys.stdout)
            sys.exit(1)

    # Parse ports
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        error_msg = f"{Fore.RED}[!] Invalid port specification: {e}{Style.RESET_ALL}"
        print(error_msg, file=sys.stderr if args.output == 'json' else sys.stdout)
        sys.exit(1)

    if not ports:
        error_msg = f"{Fore.RED}[!] No valid ports specified{Style.RESET_ALL}"
        print(error_msg, file=sys.stderr if args.output == 'json' else sys.stdout)
        sys.exit(1)

    # Check for root privileges (recommended for raw sockets)
    if sys.platform.startswith('linux') and not sys.stdout.isatty():
        output_stream = sys.stdout if args.output == 'text' else sys.stderr
        print(f"{Fore.YELLOW}[!] Warning: Running without TTY, some features may be limited{Style.RESET_ALL}", file=output_stream)

    # Create scanner instance
    scanner = UDPDiscovery(
        targets=targets,
        ports=ports,
        timeout=args.timeout,
        retries=args.retries,
        rate_limit=args.rate_limit,
        output_format=args.output
    )

    # Run the scan
    try:
        results = asyncio.run(scanner.run())
        scanner.output_results()
    except KeyboardInterrupt:
        if args.output != 'json':
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        error_msg = f"{Fore.RED}[!] Error during scan: {e}{Style.RESET_ALL}"
        print(error_msg, file=sys.stderr if args.output == 'json' else sys.stdout)
        sys.exit(1)

if __name__ == '__main__':
    main()