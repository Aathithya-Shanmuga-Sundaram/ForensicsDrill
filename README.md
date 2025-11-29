# **ForensicsDrill**

### *Interactive Incident Response & Digital Forensics Simulation CLI*

ForensicsDrill is a **hands‑on incident response simulation tool** designed for cybersecurity labs.
It generates realistic IR scenarios where students must investigate artifacts, analyze logs, inspect processes, search for indicators of compromise, and identify the root cause of the simulated attack.

The tool is fully **CLI‑based**, requires **no admin privileges**, and is ideal for restricted lab environments.

---

## ⭐ Features

* Multiple IR Scenarios (Ransomware, Exfiltration, Persistence)
* Randomized artifacts each run (prevents memorizing answers)
* Fake directory tree (logs, binaries, ransom notes, staged data, etc.)
* Process simulation (list, inspect, parent-child tracing)
* File investigation (entropy, keyword detection, heuristic flags)
* IOC scanning (automatic detection of suspicious patterns)
* Search across artifacts (grep-like)
* Timeline analysis
* JSON incident report generation
* Flag solving mechanism
* Built‑in Hints & Full Walkthrough for instructors

---

## 📦 Installation

```bash
git clone https://github.com/Aathithya-Shanmuga-Sundaram/ForensicsDrill
cd ForensicsDrill
```

No elevated privileges needed.
Runs on **Windows, Linux, macOS**.

---

## 🎮 Usage

### **1. Initialize a lab session**

```
python app.py init --session lab1
```

Initialize with a specific scenario:

```
python app.py init --session lab1 --scenario ransomware_campaign
```

Available scenarios:

* `ransomware_campaign`
* `credential_theft_exfil`
* `persistence_startup`

---

### **2. Start the interactive console**

```
python app.py start --session lab1
```

You will enter the simulation shell:

```
ForensicsDrill v1.0
FD>
```

---

## 🧪 Commands Overview

### Navigation

```
explore
ls <directory>
open <file>
timeline
```

### Investigation

```
investigate <file>
search <keyword>
ioc-scan
```

### Process Analysis

```
proc list
proc inspect <pid>
```

### Reporting & Solving

```
report
solve <FLAG>
guide
explain
```

---

## 📂 Workspace Structure

```
workspaces/
   lab1/
       disk/
       logs/
       processes.json
       scenario.json
       report.json
```

---

## 🧑‍🏫 Instructor Mode

### `guide`

High‑level hints for students.

### `explain`

Full walkthrough + correct flag
(Recommended for teachers preparing practical sessions.)

---

## 🛠 Add Your Own Scenarios

Add a new JSON file inside:

```
scenarios/
```

Define:

* file generation rules
* randomized names
* IOCs
* flags
* hints
* full explanation text

---

## 📜 License

Open‑source; use MIT License for academic use.

---

## 🤝 Contributing

Pull requests welcome — especially new scenarios.
