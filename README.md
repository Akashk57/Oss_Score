# Oss_Score
#  OSS Score – Open Source Security Analyzer

OSS Score is a lightweight CLI tool that evaluates the **security risk of open-source packages** (PyPI & npm) using real-time vulnerability data and GitHub metrics.

It helps developers make safer dependency choices by assigning a **security score (0–100)**.

---

##  Features

*  Checks vulnerabilities using OSV.dev API
*  Supports **PyPI** and **npm** packages
*  Uses GitHub stars as a popularity/maintenance signal
*  Fast (sub-2 seconds target)
*  Local caching (SQLite) for offline usage
*  Simple security score output with risk level

---

##  How It Works

OSS Score calculates a score based on:

* Number of vulnerabilities (CVEs)
* Severity indicators (critical/high)
* GitHub popularity (stars)
* Basic heuristics for risk evaluation

Score range:

*  80–100 → Low Risk
*  60–79 → Moderate Risk
*  Below 60 → High Risk

---

##  Installation

```bash
git clone https://github.com/Akashk57/Oss_Score.git
cd Oss_Score
pip install requests
```

---

##  Usage

### Basic command

```bash
python oss_score.py check <package_name>
```

### Examples

```bash
python oss_score.py check requests
python oss_score.py check express --ecosystem npm
```

### Offline mode (uses cache)

```bash
python oss_score.py check requests --offline
```

---

##  Example Output

```
Open-Source Security Score
Package : requests (PyPI)
Version : 2.x.x
Score   : 85/100

 LOW RISK - Safe to use

 1 CVEs detected
   • CVE-XXXX - Example vulnerability

 Suggestions:
   • Compare safer alternatives
   • Integrate into CI/CD
```

---

##  Project Structure

```
.
├── oss_score.py          # Core CLI tool
├── oss_security_cache.db # Local cache database
└── README.md
```

---

##  Tech Stack

* Python
* SQLite (local caching)
* OSV.dev API
* GitHub REST API

---

##  Future Improvements

* Add more ecosystems (Maven, Go, Rust)
* Better severity scoring (CVSS integration)
* Web dashboard / UI
* CI/CD GitHub Action integration
* Alternative package suggestions

---

##  Contributing

Contributions are welcome!
Feel free to open issues or submit pull requests.

---


##  Author

Aniket Chaudhary
Akash Kodali
---
