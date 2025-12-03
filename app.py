#!/usr/bin/env python3
"""
ForensicsDrill - Full IR Simulation (Mode C) - RANDOM FLAG EDITION
Flag locations randomized per session - no memorization possible!
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
import base64
import binascii
import codecs
import math


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
    target = os.path.normpath(os.path.join(wsroot, rel))
    if not target.startswith(os.path.abspath(wsroot)):
        raise ValueError("Invalid path (out of workspace)")
    return target

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    probs = [float(data.count(bytes([i])))/len(data) for i in range(256)]
    ent = 0.0
    for p in probs:
        if p > 0:
            ent -= p * math.log2(p)
    return ent

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

SCENARIO_FLAGS = {
    "ransomware_campaign": "FD{RANSOMWARE_DETECTED}",
    "credential_theft_exfil": "FD{CREDENTIALS_EXFILTRATED}",
    "persistence_startup": "FD{PERSISTENCE_FOUND}"
}

# ----------------- Randomized Flag Locations -----------------
FLAG_LOCATIONS = {
    "ransomware_campaign": [
        {"method": "base64", "path_template": "disk/README_RESTORE_FILES.txt", "content": "Recovery-key (base64): {encoded_flag}\n"},
        {"method": "plain", "path_template": "disk/.{rand6}.flag", "content": "{flag}\n"},
        {"method": "hex", "path_template": "disk/ransom_config.ini", "content": "[config]\nserial={encoded_flag}\n"},
        {"method": "rot13", "path_template": "logs/ransom_activity.log", "content": "Encoded serial: {encoded_flag}\n"},
        {"method": "fragment", "path_template": "disk/encrypted_victim_data.txt", "content": "data_chunk_42={half_flag1}{half_flag2}\n"},
        {"method": "entropy", "path_template": "disk/suspicious.bin", "content": "binary"},
    ],
    "credential_theft_exfil": [
        {"method": "plain", "path_template": "disk/creds_dump.txt", "content": "# leaked-data: {flag}\n"},
        {"method": "base64", "path_template": "disk/staged/data_part_1.csv", "content": "0,{encoded_flag}\n"},
        {"method": "hex", "path_template": "disk/.{rand6}.exfil", "content": "{encoded_flag}\n"},
        {"method": "fragment", "path_template": "logs/exfil_session.log", "content": "payload_size=42 data={half_flag1}...{half_flag2}\n"},
        {"method": "entropy", "path_template": "disk/staged/archive.bin", "content": "binary"},
        {"method": "process_cmd", "proc_name": "exfiltrator", "cmd_insert": "sid={encoded_flag}"},
    ],
    "persistence_startup": [
        {"method": "hex", "path_template": "disk/task_malicious.schtask", "content": "TaskID: {encoded_flag}\n"},
        {"method": "plain", "path_template": "disk/run_on_startup.lnk", "content": "ShortcutID: {flag}\n"},
        {"method": "base64", "path_template": "disk/.{rand6}.pers", "content": "{encoded_flag}\n"},
        {"method": "rot13", "path_template": "logs/startup_events.log", "content": "service_rot13={encoded_flag}\n"},
        {"method": "fragment", "path_template": "disk/persistence_config.txt", "content": "reg_key={half_flag1}{half_flag2}\n"},
        {"method": "process_cmd", "proc_name": "persistsvc.exe", "cmd_insert": "id={encoded_flag}"},
    ]
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

# ----------------- Flag embedding helpers -----------------
def codecs_encode_rot13(s):
    trans = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                          "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")
    return s.translate(trans)

def embed_random_flags(ws: Workspace, flag: str, scenario_key: str):
    """Embed flag in 2-3 random locations with different methods"""
    locations = FLAG_LOCATIONS.get(scenario_key, [])
    if not locations:
        return
    
    # Select 2-3 random locations
    num_locations = random.randint(2, 3)
    selected_locations = random.sample(locations, min(num_locations, len(locations)))
    
    print(info(f"Embedding flag in {len(selected_locations)} random locations..."))
    
    for loc in selected_locations:
        if "path_template" in loc:
            path = loc["path_template"].format(rand6=rand_str(6))
            full_path = os.path.join(ws.root, path)
            ensure_dir(os.path.dirname(full_path))
            
            if loc["method"] == "plain":
                content = loc["content"].format(flag=flag)
                mode = "w"
            elif loc["method"] == "base64":
                encoded = base64.b64encode(flag.encode()).decode()
                content = loc["content"].format(encoded_flag=encoded)
                mode = "a"  # append to existing files
            elif loc["method"] == "hex":
                encoded = binascii.hexlify(flag.encode()).decode()
                content = loc["content"].format(encoded_flag=encoded)
                mode = "a"
            elif loc["method"] == "rot13":
                encoded = codecs_encode_rot13(flag)
                content = loc["content"].format(encoded_flag=encoded)
                mode = "w"
            elif loc["method"] == "fragment":
                half1 = base64.b64encode(flag[:len(flag)//2].encode()).decode()
                half2 = base64.b64encode(flag[len(flag)//2:].encode()).decode()
                content = loc["content"].format(half_flag1=half1, half_flag2=half2)
                mode = "w"
            elif loc["method"] == "entropy":
                # Embed in binary file with high entropy
                with open(full_path, "wb") as f:
                    f.write(b"FAKEBINARY" + os.urandom(128) + flag.encode() + os.urandom(256))
                ts = (datetime.utcnow() - timedelta(days=random.randint(0, 90))).timestamp()
                os.utime(full_path, (ts, ts))
                print(f"  -> {path} (entropy)")
                continue
            
            # Write/append content
            if not os.path.exists(full_path):
                with open(full_path, mode) as f:
                    f.write(content)
            else:
                with open(full_path, "a") as f:
                    f.write(content)
            
            # Randomize timestamps
            ts = (datetime.utcnow() - timedelta(days=random.randint(0, 90))).timestamp()
            os.utime(full_path, (ts, ts))
            
            print(f"  -> {path} ({loc['method']})")

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
    disk_files = [f for f in os.listdir(ws.disk) if os.path.isfile(os.path.join(ws.disk, f))]
    for f in disk_files[:3]:
        src = os.path.join(ws.disk, f)
        dst = os.path.join(ws.disk, f + ".locked")
        shutil.copy(src, dst)
    note = os.path.join(ws.disk, "README_RESTORE_FILES.txt")
    with open(note, "w") as nf:
        nf.write("All your files have been encrypted. To restore send 5 BTC to ...\n")
        nf.write("Contact: attacker@example[.]onion\n")
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
        attacker_ip = ".".join(str(random.randint(1,254)) for _ in range(4))
        for i in range(3):
            f.write(f"Jan 12 09:14:{20+i} server sshd[1992]: Failed password for invalid user admin from {attacker_ip} port 4242 ssh2\n")
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

def build_process_table(scenario_key, flag=None):
    procs = []
    base = random.randint(2000, 4000)
    procs.append({"pid": 1, "name": "init", "ppid": 0, "user": "root", "cmdline": "/sbin/init"})
    procs.append({"pid": 101, "name": "sshd", "ppid": 1, "user": "root", "cmdline": "/usr/sbin/sshd -D"})
    
    if scenario_key == "ransomware_campaign":
        procs.append({"pid": base, "name": "svch0st.exe", "ppid": base-1, "user": "alice", "cmdline": "svch0st.exe /hidden /enc=base64"})
        procs.append({"pid": base-1, "name": "cmd.exe", "ppid": 101, "user": "alice", "cmdline": "cmd.exe /c start"})
    elif scenario_key == "credential_theft_exfil":
        target_ip = ".".join(str(random.randint(1,254)) for _ in range(4))
        procs.append({"pid": base, "name": "exfiltrator", "ppid": 101, "user": "bob", "cmdline": f"exfiltrator -target {target_ip}:8080"})
        procs.append({"pid": base+1, "name": "creddump", "ppid": base, "user": "bob", "cmdline": "creddump --steal"})
        # Randomly embed flag in process cmdline
        if flag and random.random() < 0.3:
            encoded = base64.b64encode(flag.encode()).decode()[:20]
            procs[-1]["cmdline"] += f" --sid={encoded}"
    elif scenario_key == "persistence_startup":
        procs.append({"pid": base, "name": "persistsvc.exe", "ppid": 101, "user": "carol", "cmdline": "persistsvc.exe --install"})
        procs.append({"pid": base+2, "name": "setup_helper", "ppid": base, "user": "carol", "cmdline": "setup_helper --reg"})
        # Randomly embed flag in process cmdline
        if flag and random.random() < 0.3:
            encoded = base64.b64encode(flag.encode()).decode()[:20]
            procs[-1]["cmdline"] += f" id={encoded}"
    
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
        # Cleanup existing content
        if os.path.exists(self.ws.root):
            for name in os.listdir(self.ws.root):
                path = os.path.join(self.ws.root, name)
                if name in ("disk","logs","processes.json","meta.json") or name.startswith("scenario_report"):
                    try:
                        if os.path.isdir(path):
                            shutil.rmtree(path)
                        else:
                            os.remove(path)
                    except Exception:
                        pass
        
        ensure_dir(self.ws.disk)
        ensure_dir(self.ws.logs)
        
        # Generate base artifacts
        generate_fake_documents(self.ws, count=6)
        create_fake_binary(self.ws, "suspicious.bin")
        create_timestomped_file(self.ws, "disk/sensitive_data.txt", days_back=random.randint(10,400))
        create_auth_log(self.ws)
        create_network_log(self.ws, entries=6, outbound=True)
        
        # Scenario-specific base artifacts (NO FLAGS)
        if self.scenario_key == "ransomware_campaign":
            create_ransom_files(self.ws)
        elif self.scenario_key == "credential_theft_exfil":
            create_staged_data(self.ws)
            with open(os.path.join(self.ws.disk, "creds_dump.txt"), "w") as f:
                f.write("user1:password123\nadmin:adminpass\n")
        elif self.scenario_key == "persistence_startup":
            with open(os.path.join(self.ws.disk, "run_on_startup.lnk"), "w") as f:
                f.write("Shortcut to malicious binary\n")
            create_persistent_task(self.ws)
        
        # CRITICAL: Embed flags in random locations AFTER base artifacts
        embed_random_flags(self.ws, self.flag, self.scenario_key)
        
        # Generate processes (may contain flag fragments)
        procs = build_process_table(self.scenario_key, self.flag)
        self.ws.write_processes(procs)
        
        # Save metadata
        self.ws.write_meta(self.meta)

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

    def ioc_scan(self):
        root = self.ws.root
        ips = set()
        findings = []
        patterns = {
            "ransom_note": re.compile(r"restore|ransom|encrypted|send \d+ btc", re.I),
            "ip": re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
            "base64": re.compile(r"[A-Za-z0-9+/]{30,}={0,2}"),
            "locked_ext": re.compile(r"\.locked$"),
            "flagfile": re.compile(r"\.flag$")
        }
        
        # Enhanced flag hunting
        flag_patterns = [
            re.compile(re.escape(self.flag), re.I),
            re.compile(base64.b64encode(self.flag.encode()).decode().rstrip("="), re.I),
            re.compile(binascii.hexlify(self.flag.encode()).decode(), re.I),
        ]
        
        for dirpath, dirnames, filenames in os.walk(root):
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                rel = os.path.relpath(p, root)
                try:
                    with open(p, "rb") as f:
                        data = f.read(20000)
                    txt = data.decode("utf-8", errors="ignore")
                    
                    # Standard IOCs
                    if patterns["ransom_note"].search(txt):
                        findings.append(("ransom_note", rel))
                        self.findings.add("ransom_note")
                    for m in patterns["ip"].findall(txt):
                        if not m.startswith("127") and not m.startswith("10") and not m.startswith("192.168"):
                            ips.add(m)
                    if patterns["base64"].search(txt):
                        findings.append(("base64_blob", rel))
                        self.findings.add("base64_blob")
                    if patterns["locked_ext"].search(rel):
                        findings.append(("encrypted_file", rel))
                        self.findings.add("encrypted_file")
                    if patterns["flagfile"].search(rel):
                        findings.append(("flag_file", rel))
                        self.findings.add("flag_file")
                    
                    # Flag hunting
                    for pat in flag_patterns:
                        if pat.search(txt):
                            print(okay(f"POTENTIAL FLAG MATCH in {rel}!"))
                            self.findings.add("potential_flag")
                            findings.append(("potential_flag", rel))
                            
                except Exception:
                    continue
        
        if not findings and not ips:
            print(info("No obvious IOCs found"))
            return
        
        print(alert("IOC-scan results:"))
        for ftype, rel in findings:
            print(f" - {ftype}: {rel}")
        
        if ips:
            print(warn("External IPs observed:"))
            for ip in sorted(ips)[:10]:
                print(f" - {ip}")
            self.findings.add("suspicious_ip")

    def investigate(self, target):
        if target.isdigit():
            self.proc_inspect(target)
            self.actions.append(("investigate_process", target, now_iso()))
            return
        try:
            p = safe_path(self.ws.root, target)
        except Exception as e:
            print(alert(str(e))); return
        if not os.path.exists(p):
            print(alert("Artifact not found"))
            return
        print(info(f"Investigating file: {target}"))
        try:
            st = os.stat(p)
            size = st.st_size
            mtime = datetime.utcfromtimestamp(st.st_mtime).isoformat() + "Z"
            print(f" - Size: {size} bytes")
            print(f" - Modified: {mtime}")
            with open(p, "rb") as f:
                sample = f.read(4096)
            ent = shannon_entropy(sample)
            print(f" - Sample entropy: {ent:.2f}")
            if ent > 5.0:
                print(alert("High entropy -> potential encrypted/packed binary"))
                self.findings.add("high_entropy")
            try:
                txt = sample.decode("utf-8", errors="ignore")
                if re.search(r"(password|passwd|user:|root|admin)", txt, re.I):
                    print(alert("Credential-like strings found"))
                    self.findings.add("credential_dump")
                if re.search(r"(ransom|encrypted|restore)", txt, re.I) or target.endswith(".locked"):
                    print(alert("Ransom note / encrypted file indicator"))
                    self.findings.add("ransom_note")
                if self.flag in txt:
                    print(okay("FLAG-like string found in this file sample!"))
                    self.findings.add("flag_found_in_file")
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
            "flag": self.flag,
            "findings": sorted(list(self.findings)),
            "actions": self.actions
        }
        path = os.path.join(self.ws.root, f"scenario_report_{int(time.time())}.json")
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        print(okay(f"Report written to {path}"))

    def submit_flag(self, flag):
        self.actions.append(("submit_flag", flag, now_iso()))
        s = flag.strip()
        canonical = s
        if canonical.lower().startswith("fd{") and canonical.endswith("}"):
            canonical = canonical
        elif not (canonical.startswith("FD{") or canonical.startswith("fd{")):
            canonical_try = f"FD{{{canonical.strip('{}')}}}"
            canonical = canonical_try
        
        if canonical.strip() == self.flag:
            print(okay("Correct flag — scenario solved! 🎉"))
            self.findings.add("scenario_solved")
            return True
        if canonical.strip().lower() == self.flag.lower():
            print(okay("Correct flag — scenario solved (case-insensitive)! 🎉"))
            self.findings.add("scenario_solved")
            return True
        print(alert("Incorrect flag"))
        return False

    def provide_guide(self):
        t = SCENARIO_TEMPLATES[self.scenario_key]
        print(f"{BOLD}{BLUE}GUIDE: {t['title']}{RESET}")
        print(t["desc"])
        print()
        print(YELLOW + "Teaching steps (flags in RANDOM locations):" + RESET)
        print(" 1) Run `explore` and `ioc-scan` to discover artifacts")
        print(" 2) Use `timeline` to spot recently modified files")
        print(" 3) `search FD{` or `search base64` patterns")
        print(" 4) `proc list` then `proc inspect <PID>` for cmdline flags")
        print(" 5) `investigate <suspicious_file>` for entropy analysis")
        print(f" FLAG: {XXXXXXXXXXXXXXXXX} (hidden in 2-3 random spots)")
        print()

    def provide_explain(self):
        print(BOLD + MAGENTA + "EXPLAIN: Step-by-step investigative workflow" + RESET)
        print("Step 1: `explore` + `ls disk/` + `ls logs/`")
        print("Step 2: `timeline` + `proc list`")
        print("Step 3: `search FD{` + `ioc-scan`")
        print("Step 4: `investigate <path>` + `proc inspect <pid>`")
        print("Step 5: `report` + `solve <FLAG>`")
        print()

    def hint(self):
        hints = {
            "ransomware_campaign": "Check .flag files, ransom_config.ini, base64 in README, suspicious.bin entropy",
            "credential_theft_exfil": "Look in staged/, creds_dump.txt, .exfil files, process cmdlines, network.log",
            "persistence_startup": "Hunt .pers files, task_malicious.schtask, run_on_startup.lnk, persistsvc.exe cmdline",
        }
        print(warn(hints.get(self.scenario_key, "Use ioc-scan + search FD{ + timeline")))

    def clear_workspace_files(self):
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
        print(f"{BOLD}{BLUE}[FORENSICS DRILL v1.0 - Developed by Aathithya Shanmuga Sundaram]")
        print(info("Flags hidden in 2-3 RANDOM locations per session! Type `help` for commands.")) 
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
                    print(info("Quitting from ForensicDrill.")); break
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
  open <path>            - view file contents
  search <term>          - search term across files (TRY: FD{{, base64)
  timeline               - file modification times (spot new flag files)
  proc list              - list processes
  proc inspect <pid>     - inspect process (flags in cmdlines!)
  ioc-scan               - scan for IOCs + FLAG PATTERNS
  investigate <artifact> - analyze file/PID (entropy, credentials)
  report                 - write findings report
  solve <FLAG>           - submit flag
  guide                  - scenario guide
  explain                - investigation workflow
  hint                   - small hint
  clear                  - clear workspace
  exit/quit              - leave shell
"""))

# ----------------- Main Entrypoint -----------------
def main():
    ap = argparse.ArgumentParser(description="ForensicsDrill - Random Flag Edition")
    sub = ap.add_subparsers(dest="cmd")
    p_init = sub.add_parser("init", help="Initialize workspace & generate scenario")
    p_init.add_argument("--session", required=True)
    p_init.add_argument("--scenario", choices=list(SCENARIO_TEMPLATES.keys()), help="force scenario")
    p_init.add_argument("--seed", type=int, help="random seed")

    p_start = sub.add_parser("start", help="Start interactive shell")
    p_start.add_argument("--session", required=True)

    args = ap.parse_args()
    if args.cmd == "init":
        session = args.session
        scenario_key = args.scenario
        seed = args.seed
        ensure_dir(os.path.join(WORKSPACES_DIR, session))
        engine = DrillEngine(session, scenario_key, seed)
        engine.init_workspace()
        print(okay(f"✅ Workspace created: {engine.ws.root}"))
        print(info(f"Scenario: {SCENARIO_TEMPLATES[engine.scenario_key]['title']}"))
        print(info(f"Seed: {engine.seed} | Flag hidden in RANDOM locations"))
        print(okay(f"Run: python app.py start --session {session}"))
    elif args.cmd == "start":
        session = args.session
        wsroot = os.path.join(WORKSPACES_DIR, session)
        if not os.path.exists(wsroot):
            print(alert("Workspace not found. Run init first."))
            sys.exit(1)
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
