#!/usr/bin/env python3
"""
ForensicsDrill - Full IR Simulation (Mode C)

Usage:
  python forensics_drill.py init --session lab1 [--seed 123]
  python forensics_drill.py start --session lab1

Features:
- Sandbox workspace under ./workspaces/<session>
- Generates directory tree with many artifacts (disk/, logs/, meta/, processes.json, network.log)
- Simulated processes, network flows, scheduled tasks, timestomped files, ransom note, staged exfil
- CLI (Style A) with commands:
    explore                  - tree view of workspace
    ls <path>                - list a directory (relative to workspace)
    open <path>              - print file contents (relative to workspace)
    search <term>            - search term across files
    timeline                 - show file modification times ordered
    proc list                - list simulated processes
    proc inspect <pid>       - inspect simulated process
    ioc-scan                 - scan for IOCs (IPs, base64, ransom note, .locked)
    investigate <artifact>   - structured analysis of file or process
    report                   - write a JSON report of findings
    solve <flag>             - submit solution flag
    guide                    - reveals steps/answers (instructor mode)
    explain                  - teaching explanation (step-by-step)
    hint                     - small hint
    clear                    - remove workspace files (keeps folder)
    help / exit
- Safe: no admin privileges required; all files are fake & local
"""

import argparse
import os
import random
import shutil
import string
import json
import sys
import time
from datetime import datetime, timedelta
import hashlib
import textwrap
import re

# ----------------- Terminal Styling (Style A) -----------------
CSI = "\033["
RESET = CSI + "0m"
BOLD = CSI + "1m"
RED = CSI + "31m"
GREEN = CSI + "32m"
YELLOW = CSI + "33m"
BLUE = CSI + "34m"
MAGENTA = CSI + "35m"
CYAN = CSI + "36m"
WHITE = CSI + "37m"

def alert(text): return f"{RED}[!] {text}{RESET}"
def info(text): return f"{CYAN}[i] {text}{RESET}"
def okay(text): return f"{GREEN}[✓] {text}{RESET}"
def warn(text): return f"{YELLOW}[~] {text}{RESET}"

# ----------------- Helpers -----------------
WORKSPACES_DIR = "workspaces"

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def rand_str(n=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def now_iso():
    return datetime.utcnow().isoformat() + "Z"

def safe_path(wsroot, rel):
    # prevent path traversal
    target = os.path.normpath(os.path.join(wsroot, rel))
    if not target.startswith(os.path.abspath(wsroot)):
        raise ValueError("Invalid path (out of workspace)")
    return target

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    probs = [float(data.count(bytes([i])))/len(data) for i in range(256)]
    ent = 0.0
    for p in probs:
        if p > 0:
            ent -= p * math.log2(p)
    return ent

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

# ----------------- Scenario Templates -----------------
SCENARIO_TEMPLATES = {
    "ransomware_campaign": {
        "title": "Ransomware campaign (multi-host simulation)",
        "indicators": ["ransom_note", "encrypted_files", "suspicious_process", "timestomp"],
        "desc": "Files renamed with .locked, ransom note dropped, suspicious process spawned and high entropy files.",
    },
    "credential_theft_exfil": {
        "title": "Credential theft + exfil",
        "indicators": ["credential_dump", "outbound_ip", "encoded_command", "staged_files"],
        "desc": "Credentials dumped to file, staged archives created and outbound connection logged.",
    },
    "persistence_startup": {
        "title": "Persistence via autoruns",
        "indicators": ["startup_entry", "scheduled_task", "unsigned_binary"],
        "desc": "Malicious scheduled task & startup entry simulated, suspicious binary present.",
    }
}

# Prebuilt "answers" (flags) for scenarios (instructor-visible)
SCENARIO_FLAGS = {
    "ransomware_campaign": "FD{RANSOMWARE_DETECTED}",
    "credential_theft_exfil": "FD{CREDENTIALS_EXFILTRATED}",
    "persistence_startup": "FD{PERSISTENCE_FOUND}"
}

# ----------------- Workspace class -----------------
class Workspace:
    def __init__(self, session):
        self.session = session
        self.root = os.path.abspath(os.path.join(WORKSPACES_DIR, session))
        self.disk = os.path.join(self.root, "disk")
        self.logs = os.path.join(self.root, "logs")
        self.meta = os.path.join(self.root, "meta.json")
        self.processes_file = os.path.join(self.root, "processes.json")
        ensure_dir(self.root)
        ensure_dir(self.disk)
        ensure_dir(self.logs)

    def write_meta(self, meta):
        with open(self.meta, "w") as f:
            json.dump(meta, f, indent=2)

    def load_meta(self):
        if not os.path.exists(self.meta):
            return {}
        with open(self.meta) as f:
            return json.load(f)

    def write_processes(self, procs):
        with open(self.processes_file, "w") as f:
            json.dump(procs, f, indent=2)

    def load_processes(self):
        if not os.path.exists(self.processes_file):
            return []
        with open(self.processes_file) as f:
            return json.load(f)

# ----------------- Artifact generators -----------------
def generate_fake_documents(ws: Workspace, folder="disk", count=8):
    created = []
    for i in range(count):
        name = f"document_{rand_str(6)}.docx"
        p = os.path.join(ws.root, folder, name)
        with open(p, "w") as f:
            f.write("Simulated report content\n")
            f.write("Document ID: " + rand_str(12) + "\n")
            f.write("Contains benign info.\n")
        created.append(p)
    return created

def create_timestomped_file(ws: Workspace, relpath, days_back=120):
    p = os.path.join(ws.root, relpath)
    ensure_dir(os.path.dirname(p))
    with open(p, "w") as f:
        f.write("Sensitive data placeholder\n")
    past = datetime.utcnow() - timedelta(days=days_back + random.randint(0,30))
    ts = past.timestamp()
    os.utime(p, (ts, ts))
    return p

def create_ransom_files(ws: Workspace):
    # take some disk files and add .locked copies
    disk_files = [f for f in os.listdir(ws.disk) if os.path.isfile(os.path.join(ws.disk, f))]
    for f in disk_files[:3]:
        src = os.path.join(ws.disk, f)
        dst = os.path.join(ws.disk, f + ".locked")
        shutil.copy(src, dst)
    note = os.path.join(ws.disk, "README_RESTORE_FILES.txt")
    with open(note, "w") as nf:
        nf.write("All your files have been encrypted. To restore send 5 BTC to ...\n")
    return note

def create_staged_data(ws: Workspace):
    staged = os.path.join(ws.disk, "staged")
    ensure_dir(staged)
    for i in range(3):
        p = os.path.join(staged, f"data_part_{i}.csv")
        with open(p, "w") as f:
            f.write("id,value\n")
            for j in range(200):
                f.write(f"{j},{rand_str(20)}\n")
    return staged

def create_network_log(ws: Workspace, entries=5, outbound=False):
    p = os.path.join(ws.logs, "network.log")
    with open(p, "w") as f:
        for i in range(entries):
            ip = ".".join(str(random.randint(1,254)) for _ in range(4))
            if outbound and i==0:
                f.write(f"OUTBOUND_CONN: {ip}:443 size={random.randint(1000,500000)}\n")
            else:
                f.write(f"CONN: {ip}:80 proto=TCP\n")
    return p

def create_auth_log(ws: Workspace):
    p = os.path.join(ws.logs, "auth.log")
    with open(p, "w") as f:
        # simulated failed attempts
        attacker_ip = ".".join(str(random.randint(1,254)) for _ in range(4))
        for i in range(3):
            f.write(f"Jan 12 09:14:{20+i} server sshd[1992]: Failed password for invalid user admin from {attacker_ip} port 4242 ssh2\n")
        # successful login later
        f.write(f"Jan 12 09:14:29 server sshd[1992]: Accepted password for root from 10.0.0.12 port 51515 ssh2\n")
    return p

def create_persistent_task(ws: Workspace):
    p = os.path.join(ws.disk, "task_malicious.schtask")
    with open(p, "w") as f:
        f.write("schtasks /create /sc onlogon /tn MalService /tr C:\\mal\\persistsvc.exe\n")
    return p

def create_fake_binary(ws: Workspace, name="suspicious.bin"):
    p = os.path.join(ws.disk, name)
    with open(p, "wb") as f:
        f.write(b"FAKEBINARY" + os.urandom(512))
    return p

def build_process_table(scenario_key):
    procs = []
    base = random.randint(2000, 4000)
    procs.append({"pid": 1, "name": "init", "ppid": 0, "user": "root", "cmdline": "/sbin/init"})
    procs.append({"pid": 101, "name": "sshd", "ppid": 1, "user": "root", "cmdline": "/usr/sbin/sshd -D"})
    # scenario specific
    if scenario_key == "ransomware_campaign":
        procs.append({"pid": base, "name": "svch0st.exe", "ppid": base-1, "user": "alice", "cmdline": "svch0st.exe /hidden /enc=base64"})
        procs.append({"pid": base-1, "name": "cmd.exe", "ppid": 101, "user": "alice", "cmdline": "cmd.exe /c start"})
    elif scenario_key == "credential_theft_exfil":
        procs.append({"pid": base, "name": "exfiltrator", "ppid": 101, "user": "bob", "cmdline": f"exfiltrator -target {'.'.join(str(random.randint(1,254)) for _ in range(4))}:8080"})
        procs.append({"pid": base+1, "name": "creddump", "ppid": base, "user": "bob", "cmdline": "creddump --steal"})
    elif scenario_key == "persistence_startup":
        procs.append({"pid": base, "name": "persistsvc.exe", "ppid": 101, "user": "carol", "cmdline": "persistsvc.exe --install"})
        procs.append({"pid": base+2, "name": "setup_helper", "ppid": base, "user": "carol", "cmdline": "setup_helper --reg"})
    # add benign procs
    for i in range(3):
        procs.append({"pid": base+10+i, "name": f"app{i}", "ppid": 101, "user": "service", "cmdline": f"app{i} --run"})
    return procs

# ----------------- Drill Engine -----------------
class DrillEngine:
    def __init__(self, session, scenario_key=None, seed=None):
        self.session = session
        self.ws = Workspace(session)
        self.seed = seed if seed is not None else random.randint(1,10**9)
        random.seed(self.seed)
        self.scenario_key = scenario_key if scenario_key else random.choice(list(SCENARIO_TEMPLATES.keys()))
        self.meta = {
            "session": session,
            "scenario_key": self.scenario_key,
            "seed": self.seed,
            "created_at": now_iso(),
            "indicators": SCENARIO_TEMPLATES[self.scenario_key]["indicators"]
        }
        self.findings = set()
        self.actions = []
        self.flag = SCENARIO_FLAGS[self.scenario_key]

    def init_workspace(self):
        # clean previous workspace (but keep base dir)
        if os.path.exists(self.ws.root):
            # remove only known content to be safe
            for name in os.listdir(self.ws.root):
                path = os.path.join(self.ws.root, name)
                if os.path.isfile(path) or os.path.isdir(path):
                    if name.startswith("scenario_report") or name in ("disk","logs","processes.json","meta.json"):
                        # remove old content
                        try:
                            if os.path.isdir(path):
                                shutil.rmtree(path)
                            else:
                                os.remove(path)
                        except Exception:
                            pass
        ensure_dir(self.ws.disk)
        ensure_dir(self.ws.logs)
        # populate artifacts
        generate_fake_documents(self.ws, count=6)
        create_fake_binary(self.ws, "suspicious.bin")
        create_timestomped_file(self.ws, "disk/sensitive_data.txt", days_back=random.randint(10,400))
        create_auth_log(self.ws)
        create_network_log(self.ws, entries=6, outbound=True)
        create_persistent_task(self.ws)
        # scenario-specific extras
        if self.scenario_key == "ransomware_campaign":
            create_ransom_files(self.ws)
        elif self.scenario_key == "credential_theft_exfil":
            create_staged_data(self.ws)
            # put credential dump
            with open(os.path.join(self.ws.disk, "creds_dump.txt"), "w") as f:
                f.write("user1:password123\nadmin:adminpass\n")
        elif self.scenario_key == "persistence_startup":
            # create startup marker file
            with open(os.path.join(self.ws.disk, "run_on_startup.lnk"), "w") as f:
                f.write("Shortcut to malicious binary\n")
        # write processes
        procs = build_process_table(self.scenario_key)
        self.ws.write_processes(procs)
        # write meta
        self.ws.write_meta(self.meta)

    # ---------------- Interaction helpers ----------------
    def list_tree(self):
        root = self.ws.root
        print(info(f"Workspace: {root}"))
        for dirpath, dirnames, filenames in os.walk(root):
            rel = os.path.relpath(dirpath, root)
            depth = rel.count(os.sep) if rel != "." else 0
            indent = "  " * depth
            base = os.path.basename(dirpath)
            print(f"{indent}{BLUE}{base}/{RESET}")
            for fn in filenames:
                print(f"{indent}  - {fn}")

    def ls(self, relpath="."):
        try:
            p = safe_path(self.ws.root, relpath)
        except Exception as e:
            print(alert(str(e))); return
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                full = os.path.join(p, name)
                if os.path.isdir(full):
                    print(f"{BLUE}{name}/{RESET}")
                else:
                    print(name)
        else:
            print(alert("Not a directory"))

    def open_file(self, relpath, max_bytes=30_000):
        try:
            p = safe_path(self.ws.root, relpath)
        except Exception as e:
            print(alert(str(e))); return
        if not os.path.exists(p):
            print(alert("File not found"))
            return
        try:
            with open(p, "rb") as f:
                data = f.read(max_bytes)
            # try decode sensible text
            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                text = str(data)
            print(f"{MAGENTA}--- BEGIN {relpath} ---{RESET}")
            print(text)
            print(f"{MAGENTA}--- END {relpath} ---{RESET}")
        except Exception as e:
            print(alert(f"Could not read file: {e}"))

    def search(self, term):
        root = self.ws.root
        matches = []
        for dirpath, dirnames, filenames in os.walk(root):
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                try:
                    with open(p, "r", errors="ignore") as f:
                        txt = f.read()
                    if term.lower() in txt.lower():
                        rel = os.path.relpath(p, root)
                        matches.append(rel)
                except Exception:
                    continue
        if not matches:
            print(info("No matches found"))
            return
        print(info(f"Found {len(matches)} matches:"))
        for m in matches:
            print(f" - {m}")

    def timeline(self):
        files = []
        for dirpath, dirnames, filenames in os.walk(self.ws.root):
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                try:
                    mtime = os.path.getmtime(p)
                    files.append((mtime, os.path.relpath(p, self.ws.root)))
                except Exception:
                    continue
        files.sort(reverse=True)
        print(info("Files by modified time (newest first):"))
        for m, rel in files[:200]:
            dt = datetime.utcfromtimestamp(m).isoformat() + "Z"
            print(f" - {rel}  [{dt}]")

    def proc_list(self):
        procs = self.ws.load_processes()
        print(info("Simulated process table:"))
        for p in procs:
            print(f" PID {p['pid']:<6} {p['name']:<20} user={p['user']}")

    def proc_inspect(self, pid):
        procs = self.ws.load_processes()
        match = None
        for p in procs:
            if str(p["pid"]) == str(pid):
                match = p; break
        if not match:
            print(alert("PID not found"))
            return
        print(f"{BOLD}{BLUE}Process: {match['name']} (PID {match['pid']}){RESET}")
        print(f"  Parent PID: {match.get('ppid')}")
        print(f"  User: {match.get('user')}")
        print(f"  Command line: {match.get('cmdline')}")
        cmd = match.get('cmdline','')
        if "base64" in cmd or "enc" in cmd or re.search(r"[A-Za-z0-9+/]{20,}", cmd):
            print(alert("Encoded/obfuscated command detected"))
            self.findings.add("encoded_command")
        if "." in match['name'] or match['name'].endswith(".exe"):
            print(warn("Unknown binary name / .exe observed"))
            self.findings.add("unsigned_binary")

    # IOC scan heuristics
    def ioc_scan(self):
        root = self.ws.root
        ips = set()
        findings = []
        patterns = {
            "ransom_note": re.compile(r"restore|ransom|encrypted|send \d+ btc", re.I),
            "ip": re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
            "base64": re.compile(r"[A-Za-z0-9+/]{30,}={0,2}"),
            "locked_ext": re.compile(r"\.locked$")
        }
        for dirpath, dirnames, filenames in os.walk(root):
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                rel = os.path.relpath(p, root)
                try:
                    with open(p, "rb") as f:
                        data = f.read(20000)
                    txt = data.decode("utf-8", errors="ignore")
                    if patterns["ransom_note"].search(txt):
                        findings.append(("ransom_note", rel))
                    for m in patterns["ip"].findall(txt):
                        # basic ip filter
                        if not m.startswith("127") and not m.startswith("10") and not m.startswith("192.168"):
                            ips.add(m)
                    if patterns["base64"].search(txt):
                        findings.append(("base64_blob", rel))
                    if patterns["locked_ext"].search(rel):
                        findings.append(("encrypted_file", rel))
                except Exception:
                    continue
        # print summary
        if not findings and not ips:
            print(info("No obvious IOCs found"))
            return
        print(alert("IOC-scan results:"))
        for ftype, rel in findings:
            print(f" - {ftype}: {rel}")
            self.findings.add(ftype)
        if ips:
            print(warn("External IPs observed:"))
            for ip in sorted(ips)[:10]:
                print(f" - {ip}")
            self.findings.add("suspicious_ip")

    def investigate(self, target):
        """
        Smart investigator: if target looks like PID -> proc_inspect
                             if looks like file -> analyze file heuristics
        """
        if target.isdigit():
            self.proc_inspect(target)
            self.actions.append(("investigate_process", target, now_iso()))
            return
        # otherwise file path
        try:
            p = safe_path(self.ws.root, target)
        except Exception as e:
            print(alert(str(e))); return
        if not os.path.exists(p):
            print(alert("Artifact not found"))
            return
        # basic file analysis
        print(info(f"Investigating file: {target}"))
        try:
            st = os.stat(p)
            size = st.st_size
            mtime = datetime.utcfromtimestamp(st.st_mtime).isoformat() + "Z"
            print(f" - Size: {size} bytes")
            print(f" - Modified: {mtime}")
            # entropy sample
            with open(p, "rb") as f:
                sample = f.read(4096)
            ent = shannon_entropy(sample)
            print(f" - Sample entropy: {ent:.2f}")
            if ent > 5.0:
                print(alert("High entropy -> potential encrypted/packed binary"))
                self.findings.add("high_entropy")
            # textual heuristics
            try:
                txt = sample.decode("utf-8", errors="ignore")
                if re.search(r"(password|passwd|user:|root|admin)", txt, re.I):
                    print(alert("Credential-like strings found"))
                    self.findings.add("credential_dump")
                if re.search(r"(ransom|encrypted|restore)", txt, re.I) or target.endswith(".locked"):
                    print(alert("Ransom note / encrypted file indicator"))
                    self.findings.add("ransom_note")
            except Exception:
                pass
            self.actions.append(("investigate_file", target, now_iso()))
        except Exception as e:
            print(alert(f"Error analyzing file: {e}"))

    def write_report(self):
        report = {
            "session": self.session,
            "scenario_key": self.scenario_key,
            "seed": self.seed,
            "created_at": now_iso(),
            "findings": sorted(list(self.findings)),
            "actions": self.actions
        }
        path = os.path.join(self.ws.root, f"scenario_report_{int(time.time())}.json")
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        print(okay(f"Report written to {path}"))

    def submit_flag(self, flag):
        self.actions.append(("submit_flag", flag, now_iso()))
        if flag.strip() == self.flag:
            print(okay("Correct flag — scenario solved"))
            self.findings.add("scenario_solved")
            return True
        else:
            print(alert("Incorrect flag"))
            return False

    def provide_guide(self):
        # teacher-level: show steps and exact flag
        t = SCENARIO_TEMPLATES[self.scenario_key]
        print(f"{BOLD}{BLUE}GUIDE: {t['title']}{RESET}")
        print(t["desc"])
        print()
        print(YELLOW + "Teaching steps (high level):" + RESET)
        if self.scenario_key == "ransomware_campaign":
            print(" 1) Explore disk/ and logs/; look for .locked files and ransom note")
            print(" 2) Inspect processes.json for suspicious svch0st.exe/cmd chains")
            print(" 3) Run ioc-scan to find ransom_note & encrypted files")
            print(f" FLAG: {self.flag}")
        elif self.scenario_key == "credential_theft_exfil":
            print(" 1) Search for creds_dump or staged files in disk/staged/")
            print(" 2) Inspect network.log for outbound connections")
            print(" 3) Inspect processes for exfiltrator/creddump")
            print(f" FLAG: {self.flag}")
        elif self.scenario_key == "persistence_startup":
            print(" 1) Look for scheduled tasks / run_on_startup.lnk")
            print(" 2) Inspect processes for persistsvc.exe")
            print(f" FLAG: {self.flag}")
        else:
            print("Generic: explore workspace, run ioc-scan, investigate suspicious artifacts")
        print()

    def provide_explain(self):
        # step-by-step teaching explanation
        print(BOLD + MAGENTA + "EXPLAIN: Step-by-step investigative workflow" + RESET)
        print("Step 1: Explore workspace: `explore` and `ls disk` / `ls logs`")
        print("Step 2: Run `timeline` and `proc list` to spot recent changes and suspect processes")
        print("Step 3: Use `search password` or `search ransom` to find artifacts quickly")
        print("Step 4: Analyze suspicious files with `investigate <path>` and inspect processes with `proc inspect <pid>`")
        print("Step 5: Run `ioc-scan` to gather IOCs and summarize findings")
        print("Step 6: Produce a `report` and submit `solve <FLAG>`")
        print()

    def hint(self):
        hints = {
            "ransomware_campaign": "Look for .locked files and a README_RESTORE_FILES.txt in disk/",
            "credential_theft_exfil": "Search for 'creds' or check disk/staged and network.log",
            "persistence_startup": "Check for startup shortcuts and scheduled task files in disk/",
        }
        print(warn(hints.get(self.scenario_key, "Explore disk/ and logs/")))

    def clear_workspace_files(self):
        # remove generated content but keep workspace dir
        for path in (self.ws.disk, self.ws.logs, self.ws.processes_file, self.ws.meta):
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path)
                elif os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass
        ensure_dir(self.ws.disk)
        ensure_dir(self.ws.logs)
        print(okay("Workspace cleared (generated content removed)."))

# ----------------- CLI Shell -----------------
class Shell:
    def __init__(self, engine: DrillEngine):
        self.e = engine

    def run(self):
        print(f"{BOLD}{BLUE}[FORENSICS DRILL v1.0]{RESET}\n{info('Type `help` for commands. Ctrl+C to exit.')}")
        while True:
            try:
                cmdline = input("\n> ").strip()
            except KeyboardInterrupt:
                print("\n" + info("Exiting shell.")); break
            if not cmdline:
                continue
            parts = cmdline.split()
            cmd = parts[0].lower()
            args = parts[1:]
            try:
                if cmd == "help":
                    self.print_help()
                elif cmd == "explore":
                    self.e.list_tree()
                elif cmd == "ls":
                    self.e.ls(args[0] if args else ".")
                elif cmd == "open":
                    if not args:
                        print(alert("Usage: open <relative_path>"))
                    else:
                        self.e.open_file(" ".join(args))
                elif cmd == "search":
                    if not args:
                        print(alert("Usage: search <term>"))
                    else:
                        self.e.search(" ".join(args))
                elif cmd == "timeline":
                    self.e.timeline()
                elif cmd == "proc":
                    if not args:
                        print(alert("Usage: proc <list|inspect> [pid]"))
                    elif args[0] == "list":
                        self.e.proc_list()
                    elif args[0] == "inspect":
                        if len(args) < 2:
                            print(alert("Usage: proc inspect <pid>"))
                        else:
                            self.e.proc_inspect(args[1])
                    else:
                        print(alert("Unknown proc subcommand"))
                elif cmd == "ioc-scan":
                    self.e.ioc_scan()
                elif cmd == "investigate":
                    if not args:
                        print(alert("Usage: investigate <artifact_or_pid>"))
                    else:
                        self.e.investigate(" ".join(args))
                elif cmd == "report":
                    self.e.write_report()
                elif cmd == "solve":
                    if not args:
                        print(alert("Usage: solve <FLAG>"))
                    else:
                        self.e.submit_flag(" ".join(args))
                elif cmd == "guide":
                    self.e.provide_guide()
                elif cmd == "explain":
                    self.e.provide_explain()
                elif cmd == "hint":
                    self.e.hint()
                elif cmd == "clear":
                    self.e.clear_workspace_files()
                elif cmd == "exit" or cmd == "quit":
                    print(info("Bye.")); break
                else:
                    print(alert("Unknown command. Type 'help' for available commands."))
            except Exception as exc:
                print(alert(f"Internal error: {exc}"))

    def print_help(self):
        print(textwrap.dedent(f"""
{CYAN}Available commands:{RESET}
  help                   - show this help
  explore                - show workspace tree
  ls <path>              - list a directory
  open <path>            - view file contents (relative to workspace)
  search <term>          - search term across files
  timeline               - show file modification times
  proc list              - list simulated processes
  proc inspect <pid>     - inspect a simulated process
  ioc-scan               - scan workspace for IOCs (ransom notes, IPs, base64)
  investigate <artifact> - investigate a file path or PID
  report                 - write a findings report (JSON)
  solve <FLAG>           - submit the scenario flag
  guide                  - instructor guide + answer
  explain                - teaching step-by-step explanation
  hint                   - small hint
  clear                  - clear generated workspace files
  exit / quit            - leave the shell
"""))

# ----------------- Main Entrypoint -----------------
def main():
    ap = argparse.ArgumentParser(description="ForensicsDrill - Full IR Simulation")
    sub = ap.add_subparsers(dest="cmd")
    p_init = sub.add_parser("init", help="Initialize workspace & generate scenario")
    p_init.add_argument("--session", required=True)
    p_init.add_argument("--scenario", choices=list(SCENARIO_TEMPLATES.keys()), help="force scenario key")
    p_init.add_argument("--seed", type=int, help="random seed for reproducibility")

    p_start = sub.add_parser("start", help="Start interactive shell for session")
    p_start.add_argument("--session", required=True)

    args = ap.parse_args()
    if args.cmd == "init":
        session = args.session
        scenario_key = args.scenario
        seed = args.seed
        wsroot = os.path.join(WORKSPACES_DIR, session)
        ensure_dir(wsroot)
        engine = DrillEngine(session, scenario_key, seed)
        engine.init_workspace()
        print(okay(f"Workspace created at {engine.ws.root}"))
        print(info(f"Scenario: {SCENARIO_TEMPLATES[engine.scenario_key]['title']} (key={engine.scenario_key})"))
        print(info(f"Seed: {engine.seed}"))
        print(info(f"Run: python forensics_drill.py start --session {session}"))
    elif args.cmd == "start":
        session = args.session
        wsroot = os.path.join(WORKSPACES_DIR, session)
        if not os.path.exists(wsroot):
            print(alert("Workspace not found. Run init first."))
            sys.exit(1)
        # start engine using meta if available
        meta_path = os.path.join(wsroot, "meta.json")
        meta = None
        if os.path.exists(meta_path):
            try:
                with open(meta_path) as f:
                    meta = json.load(f)
            except Exception:
                meta = None
        if meta:
            engine = DrillEngine(session, meta.get("scenario_key"), meta.get("seed"))
        else:
            engine = DrillEngine(session)
        shell = Shell(engine)
        shell.run()
    else:
        ap.print_help()

if __name__ == "__main__":
    main()
