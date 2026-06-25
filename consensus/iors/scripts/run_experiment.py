#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0

import argparse
import csv
import getpass
import re
import shlex
import sys
import time
from datetime import datetime
from pathlib import Path

import pexpect


REPO_ROOT = Path(__file__).resolve().parents[3]
IORS_DIR = REPO_ROOT / "consensus" / "iors"
HOST_DIR = REPO_ROOT / "consensus" / "common" / "host"
DEFAULT_RESULTS_DIR = IORS_DIR / "results"

COMMIT_RE = re.compile(
    r"execution commit batch=(?P<batch>\d+) seqs=(?P<first>\d+)-(?P<last>\d+) "
    r"digest=(?P<digest>0x[0-9a-fA-F]+).*?batch_latency_ms=(?P<batch_latency>[0-9.]+) "
    r"batch_throughput_tps=(?P<batch_tps>[0-9.]+).*?committed_txs=(?P<committed_txs>\d+) "
    r"throughput_tps=(?P<throughput>[0-9.]+)"
)
TX_LATENCY_RE = re.compile(
    r"tx_latency batch=(?P<batch>\d+) seq=(?P<seq>\d+) "
    r"spec_time=(?P<spec_time>[0-9.]+) commit_time=(?P<commit_time>[0-9.]+) "
    r"latency_ms=(?P<latency_ms>[0-9.]+)"
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run one automated BIDL/IORS Mininet experiment and collect metrics."
    )
    parser.add_argument("--batch-size", type=int, required=True)
    parser.add_argument("--tx-rate", type=float, required=True,
                        help="Leader send rate in transactions per second")
    parser.add_argument("--tx-count", type=int,
                        help="Total transactions; defaults to one full batch")
    parser.add_argument("--attack", choices=["none", "duplicate", "conflict", "reorder"],
                        default="none")
    parser.add_argument("--attack-mode", choices=["active", "listen"], default="active")
    parser.add_argument("--attack-sequence", type=int, default=10)
    parser.add_argument("--attack-start", type=float, default=0.1,
                        help="Delay before active attack injection")
    parser.add_argument("--commit-delay", type=float, default=0.2)
    parser.add_argument("--leader-destinations", default="10.0.2.2,10.0.3.3")
    parser.add_argument("--result-dir", type=Path,
                        help="Directory for logs and CSV files")
    parser.add_argument("--timeout", type=float, default=120.0,
                        help="Seconds to wait for all expected commits")
    parser.add_argument("--sudo-password",
                        help="Optional sudo password for make run; otherwise prompt if needed")
    parser.add_argument("--verbose", action="store_true",
                        help="Mirror Mininet output while running")
    return parser.parse_args()


def shell_quote(value):
    return shlex.quote(str(value))


class MininetSession:
    def __init__(self, cwd, sudo_password=None, verbose=False):
        self.cwd = cwd
        self.sudo_password = sudo_password
        self.verbose = verbose
        self.password_sent = False
        self.child = None

    def start(self):
        self.child = pexpect.spawn(
            "make",
            ["run"],
            cwd=str(self.cwd),
            encoding="utf-8",
            timeout=90,
        )
        if self.verbose:
            self.child.logfile = sys.stdout
        self._expect_prompt(timeout=90)

    def _expect_prompt(self, timeout):
        while True:
            matched = self.child.expect(
                [r"mininet>", r"\[sudo\].*密码", r"\[sudo\].*password", pexpect.EOF, pexpect.TIMEOUT],
                timeout=timeout,
            )
            if matched == 0:
                return
            if matched in (1, 2):
                password = self.sudo_password
                if password is None:
                    password = getpass.getpass("sudo password for make run: ")
                self.child.sendline(password)
                self.password_sent = True
                continue
            if matched == 3:
                raise RuntimeError("make run exited before Mininet prompt")
            raise TimeoutError("Timed out waiting for Mininet prompt")

    def run(self, command, timeout=30):
        if self.verbose:
            print(f"\n[mininet] {command}")
        self.child.sendline(command)
        self._expect_prompt(timeout=timeout)

    def stop(self):
        if self.child is None:
            return
        if self.child.isalive():
            try:
                self.child.sendline("exit")
                self.child.expect(pexpect.EOF, timeout=10)
            except Exception:
                self.child.terminate(force=True)


def mininet_host_command(host, command, *, background=True, log=None):
    if log is not None:
        command = f"{command} > {shell_quote(log)} 2>&1"
    if background:
        command = f"{command} &"
    return f"{host} sh -c {shell_quote(command)}"


def make_result_dir(args):
    if args.result_dir:
        result_dir = args.result_dir.resolve()
    else:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        name = (
            f"batch{args.batch_size}_rate{int(args.tx_rate)}_"
            f"tx{args.tx_count}_attack-{args.attack}_{stamp}"
        )
        result_dir = DEFAULT_RESULTS_DIR / name
    result_dir.mkdir(parents=True, exist_ok=True)
    return result_dir


def wait_for_commits(execution_log, expected_batches, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if execution_log.exists():
            commits = COMMIT_RE.findall(execution_log.read_text(errors="replace"))
            if len(commits) >= expected_batches:
                return True
        time.sleep(0.5)
    return False


def parse_metrics(result_dir):
    leader_log = result_dir / "leader.log"
    consensus_log = result_dir / "consensus.log"
    execution_log = result_dir / "execution.log"
    malicious_log = result_dir / "malicious.log"

    leader_sent = count_lines(leader_log, "leader tx")
    consensus_received = count_lines(consensus_log, "consensus received")
    execution_speculative = count_lines(execution_log, "execution speculative")

    commits = []
    tx_latencies = []
    if execution_log.exists():
        for line in execution_log.read_text(errors="replace").splitlines():
            commit = COMMIT_RE.search(line)
            if commit:
                row = commit.groupdict()
                row["batch"] = int(row["batch"])
                row["first"] = int(row["first"])
                row["last"] = int(row["last"])
                row["batch_latency"] = float(row["batch_latency"])
                row["batch_tps"] = float(row["batch_tps"])
                row["committed_txs"] = int(row["committed_txs"])
                row["throughput"] = float(row["throughput"])
                commits.append(row)
                continue
            latency = TX_LATENCY_RE.search(line)
            if latency:
                row = latency.groupdict()
                row["batch"] = int(row["batch"])
                row["seq"] = int(row["seq"])
                row["spec_time"] = float(row["spec_time"])
                row["commit_time"] = float(row["commit_time"])
                row["latency_ms"] = float(row["latency_ms"])
                tx_latencies.append(row)

    write_csv(result_dir / "commits.csv", commits)
    write_csv(result_dir / "tx_latencies.csv", tx_latencies)

    summary = {
        "leader_sent_packets": leader_sent,
        "consensus_received_txs": consensus_received,
        "execution_speculative_txs": execution_speculative,
        "committed_batches": len(commits),
        "committed_txs": commits[-1]["committed_txs"] if commits else 0,
        "throughput_tps": commits[-1]["throughput"] if commits else 0.0,
        "tx_latency_count": len(tx_latencies),
        "tx_latency_avg_ms": (
            sum(row["latency_ms"] for row in tx_latencies) / len(tx_latencies)
            if tx_latencies else 0.0
        ),
        "tx_latency_min_ms": min((row["latency_ms"] for row in tx_latencies), default=0.0),
        "tx_latency_max_ms": max((row["latency_ms"] for row in tx_latencies), default=0.0),
        "malicious_log": str(malicious_log) if malicious_log.exists() else "",
    }
    write_csv(result_dir / "summary.csv", [summary])
    return summary, commits, tx_latencies


def count_lines(path, prefix):
    if not path.exists():
        return 0
    return sum(1 for line in path.read_text(errors="replace").splitlines()
               if line.startswith(prefix))


def write_csv(path, rows):
    if not rows:
        path.write_text("")
        return
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def run_experiment(args):
    args.tx_count = args.tx_count or args.batch_size
    if args.tx_count <= 0:
        raise ValueError("--tx-count must be positive")
    if args.batch_size <= 0:
        raise ValueError("--batch-size must be positive")

    result_dir = make_result_dir(args)
    expected_batches = (args.tx_count + args.batch_size - 1) // args.batch_size
    leader_destinations = args.leader_destinations
    if args.attack != "none" and args.attack_mode == "listen" and "10.0.4.4" not in leader_destinations:
        leader_destinations = f"{leader_destinations},10.0.4.4"

    logs = {
        "leader": result_dir / "leader.log",
        "consensus": result_dir / "consensus.log",
        "execution": result_dir / "execution.log",
        "malicious": result_dir / "malicious.log",
    }

    session = MininetSession(
        IORS_DIR,
        sudo_password=args.sudo_password,
        verbose=args.verbose,
    )
    try:
        print(f"Starting Mininet/BMv2, results: {result_dir}")
        session.start()

        consensus_cmd = (
            f"python3 {shell_quote(HOST_DIR / 'bidl_consensus.py')} "
            f"--execution-dest 10.0.3.3 "
            f"--batch-size {args.batch_size} "
            f"--commit-delay {args.commit_delay}"
        )
        execution_cmd = (
            f"python3 {shell_quote(HOST_DIR / 'bidl_execution.py')} "
            f"--print-tx-latency"
        )
        session.run(mininet_host_command("h2", consensus_cmd, log=logs["consensus"]))
        session.run(mininet_host_command("h3", execution_cmd, log=logs["execution"]))

        if args.attack != "none":
            malicious_cmd = (
                f"python3 {shell_quote(HOST_DIR / 'bidl_malicious.py')} "
                f"--mode {args.attack_mode} "
                f"--attack {args.attack} "
                f"--destination 10.0.3.3 "
                f"--sequence {args.attack_sequence}"
            )
            if args.attack_mode == "active" and args.attack_start > 0:
                malicious_cmd = f"sleep {args.attack_start}; {malicious_cmd}"
            session.run(mininet_host_command("h4", malicious_cmd, log=logs["malicious"]))

        leader_cmd = (
            f"python3 {shell_quote(HOST_DIR / 'bidl_leader.py')} "
            f"--destinations {shell_quote(leader_destinations)} "
            f"--start-sequence 0 "
            f"--tx-count {args.tx_count} "
            f"--batch-size {args.batch_size} "
            f"--tx-rate {args.tx_rate}"
        )
        session.run(mininet_host_command("h1", leader_cmd, background=False, log=logs["leader"]),
                    timeout=max(60, int(args.tx_count / max(args.tx_rate, 1.0)) + 60))

        if not wait_for_commits(logs["execution"], expected_batches, args.timeout):
            print("Warning: timed out before all expected commits were observed", file=sys.stderr)
    finally:
        session.stop()

    summary, commits, tx_latencies = parse_metrics(result_dir)
    print_summary(result_dir, summary, commits, tx_latencies)


def print_summary(result_dir, summary, commits, tx_latencies):
    print("\nExperiment summary")
    print(f"  results: {result_dir}")
    print(f"  leader_sent_packets: {summary['leader_sent_packets']}")
    print(f"  consensus_received_txs: {summary['consensus_received_txs']}")
    print(f"  execution_speculative_txs: {summary['execution_speculative_txs']}")
    print(f"  committed_batches: {summary['committed_batches']}")
    print(f"  committed_txs: {summary['committed_txs']}")
    print(f"  throughput_tps: {summary['throughput_tps']:.2f}")
    print(f"  tx_latency_count: {summary['tx_latency_count']}")
    print(f"  tx_latency_avg_ms: {summary['tx_latency_avg_ms']:.3f}")
    print(f"  tx_latency_min_ms: {summary['tx_latency_min_ms']:.3f}")
    print(f"  tx_latency_max_ms: {summary['tx_latency_max_ms']:.3f}")
    if commits:
        print("\nCommitted batches")
        for commit in commits:
            print(
                f"  batch={commit['batch']} seqs={commit['first']}-{commit['last']} "
                f"latency_ms={commit['batch_latency']:.3f} "
                f"batch_tps={commit['batch_tps']:.2f} "
                f"total_tps={commit['throughput']:.2f}"
            )
    if tx_latencies:
        print("\nPer-transaction latency")
        print(f"  full CSV: {result_dir / 'tx_latencies.csv'}")
        for row in tx_latencies[:10]:
            print(f"  seq={row['seq']} latency_ms={row['latency_ms']:.3f}")
        if len(tx_latencies) > 10:
            print(f"  ... {len(tx_latencies) - 10} more rows")


def main():
    args = parse_args()
    run_experiment(args)


if __name__ == "__main__":
    main()
