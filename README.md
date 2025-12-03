# 🕵️‍♂️ ForensicsDrill — Interactive DFIR Training Simulator

[![Python 3.6+](https://img.shields.io/badge/Python-3.6%2B-blue.svg)](https://www.python.org/)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-green.svg)](https://www.python.org/)
[![Cybersecurity Lab](https://img.shields.io/badge/%23MakeEveryoneCyberSafe-orange.svg)](https://github.com/Aathithya-Shanmuga-Sundaram)


A fully offline, zero‑dependency digital forensics lab simulator designed for universities, cybersecurity clubs, and training centers. Every session generates **unique evidence**, **random flag placements**, and **realistic artifacts**, forcing students to investigate not memorize.

---

## 🔥 What This Project Is

A hands-on DFIR environment where learners:

* Explore a simulated compromised workstation
* Inspect malicious files and processes
* Perform IOC scanning & timeline analysis
* Extract and decode real flags hidden in **randomized locations**
* Submit findings and generate a JSON report

Students interact with the system using custom forensic commands, no OS-level access required.

---

## 🎯 Key Features

### **1. Randomized Flag System**

* Each scenario contains **6+ possible hiding spots**
* Only **2–3 are selected per session**
* Flags may appear as:

  * Plaintext files
  * Base64/hex/rot13 encoded
  * Embedded within config files
  * Hidden inside fake process command-line arguments
  * High‑entropy "suspicious" blobs

### **2. Three Realistic Incident Scenarios**

| Scenario                            | Core Flag                     | Themes                                                       |
| ----------------------------------- | ----------------------------- | ------------------------------------------------------------ |
| **Ransomware Campaign**             | `FD{XXXXXXXXXXXXXXXXXXX}`     | Locked files, ransom notes, rogue processes, encryption keys |
| **Credential Theft & Exfiltration** | `FD{XXXXXXXXXXXXXXXXXXXXXXX}` | Credential dumping, C2 activity, staged archives             |
| **Persistence Startup Compromise**  | `FD{XXXXXXXXXXXXXXXXX}`       | Autoruns, malicious services, registry artifacts             |

### **3. 100% Python Standard Library**

No extra packages. No pip. Works on:

* Linux
* Windows
* macOS
* Air‑gapped labs
* Educational VMs

### **4. Investigation-Focused Command Shell**

Students interact using a realistic command-style interface:

```
explore                  # Show workspace map
ls <path>                # List directory
open <file>              # View file content
search <keyword>         # Search recursively
timeline                 # Show modification activity
proc list                # List processes
proc inspect <pid>       # View process details
ioc-scan                 # Automated IOC hunt
investigate <file/pid>   # Entropy + suspicious indicators
report                   # Export JSON findings
solve <FLAG>             # Submit discovered flag
hint                     # One clue
guide                    # Explains step-by-step
```

---

## 🚀 Quick Start

### **1. Clone the Project**

```bash
git clone https://github.com/Aathithya-Shanmuga-Sundaram/ForensicsDrill.git
cd ForensicsDrill
```

### **2. Initialize a new session**

```bash
python app.py init --session lab1
```

Generates:

* Random files
* Random flagged artifacts
* Scenario metadata
* Fake process table

### **3. Start the investigation**

```bash
python app.py start --session lab1
```

You will enter the command shell.

---

## 🧪 Example Student Workflow

```
explore
ioc-scan
timeline
search "FD{"
proc list
proc inspect 1048
open disk/README_RESTORE_FILES.txt
solve FD{RANSOMWARE_DETECTED}
```

**Example Output:**

```
✓ Correct — scenario solved.
Report saved to: workspace/lab1/report.json
```

---

## 🎓 Ideal For

* Cybersecurity degree programs
* DFIR training workshops
* Cyber clubs and CTF teams
* Ransomware and OSINT teaching modules
* Independent learners building real skills

---

## 🤝 Contributing

1. Add new scenarios
2. Define new flag hiding patterns
3. Test with:

```bash
python app.py init --session test --seed {SEED}
```

4. Submit a pull request
