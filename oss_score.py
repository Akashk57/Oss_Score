import argparse
import requests
import sqlite3
import json
import time
from datetime import datetime
from urllib.parse import urlparse

DB_NAME = 'oss_security_cache.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS cache
                 (package TEXT, ecosystem TEXT, version TEXT, score INTEGER, data TEXT, timestamp INTEGER)''')
    conn.commit()
    conn.close()

def get_cached(package, ecosystem, version):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT score, data, timestamp FROM cache WHERE package=? AND ecosystem=? AND version=?", (package, ecosystem, version))
    row = c.fetchone()
    conn.close()
    if row:
        score, data_str, ts = row
        if time.time() - ts < 86400:  # 24 hours
            return score, json.loads(data_str)
    return None, None

def save_cache(package, ecosystem, version, score, data):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("REPLACE INTO cache VALUES (?,?,?,?,?,?)", (package, ecosystem, version, score, json.dumps(data), int(time.time())))
    conn.commit()
    conn.close()

def get_latest_version(package, ecosystem):
    if ecosystem == "PyPI":
        try:
            r = requests.get(f"https://pypi.org/pypi/{package}/json", timeout=5)
            if r.status_code == 200:
                return r.json()['info']['version']
        except:
            pass
    else:  # npm
        try:
            r = requests.get(f"https://registry.npmjs.org/{package}", timeout=5)
            if r.status_code == 200:
                return r.json().get('dist-tags', {}).get('latest')
        except:
            pass
    return None

def query_osv(package, ecosystem, version=None):
    url = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": package, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version
    try:
        r = requests.post(url, json=payload, timeout=5)
        if r.status_code == 200:
            return r.json().get("vulns", [])
    except:
        pass
    return []

def get_pypi_info(package):
    try:
        r = requests.get(f"https://pypi.org/pypi/{package}/json", timeout=5)
        if r.status_code == 200:
            info = r.json()['info']
            return {'project_urls': info.get('project_urls', {})}
    except:
        pass
    return None

def get_npm_info(package):
    try:
        r = requests.get(f"https://registry.npmjs.org/{package}", timeout=5)
        if r.status_code == 200:
            data = r.json()
            return {'repository': data.get('repository', {})}
    except:
        pass
    return None

def extract_github_repo(info, ecosystem):
    if not info:
        return None
    if ecosystem == "PyPI":
        for url in info.get('project_urls', {}).values():
            if 'github.com' in url.lower():
                path = urlparse(url).path.strip('/').split('/')
                if len(path) >= 2:
                    return f"{path[0]}/{path[1]}"
    else:  # npm
        repo = info.get('repository')
        if isinstance(repo, dict) and 'url' in repo:
            url = repo['url']
            if 'github.com' in url:
                path = urlparse(url).path.strip('/').split('/')
                if len(path) >= 2:
                    return f"{path[0]}/{path[1]}"
    return None

def get_github_metrics(repo):
    if not repo:
        return {'stars': 0}
    try:
        r = requests.get(f"https://api.github.com/repos/{repo}", timeout=5)
        if r.status_code == 200:
            data = r.json()
            return {'stars': data.get('stargazers_count', 0)}
    except:
        pass
    return {'stars': 0}

def calculate_score(vulns, github_info):
    score = 100
    
    # Improved vuln penalty (severity aware + less aggressive)
    if vulns:
        penalty = len(vulns) * 12
        # Extra for critical/high
        for v in vulns:
            summary = str(v.get('summary', '')).lower()
            if 'critical' in summary or 'high' in summary:
                penalty += 18
        score -= penalty
    
    # Popularity + Maintenance bonus
    stars = github_info.get('stars', 0)
    if stars > 5000:
        score += 12
    elif stars > 1000:
        score += 8
    elif stars < 100:
        score -= 15
    
    # Minimum score floor
    return max(10, min(100, int(score)))

def print_result(package, ecosystem, version, score, vulns, github_info):
    print(f"\n🔒 Open-Source Security Score")
    print(f"Package : {package} ({ecosystem})")
    print(f"Version : {version or 'latest'}")
    print(f"Score   : {score}/100\n")
    
    if score >= 80:
        print(" LOW RISK - Safe to use")
    elif score >= 60:
        print("️  MODERATE RISK - Review before install")
    else:
        print(" HIGH RISK - Avoid or find alternative")
    
    if vulns:
        print(f"\n {len(vulns)} CVEs detected (affecting this version)")
        for v in vulns[:5]:
            print(f"   • {v.get('id')} - {v.get('summary', '')[:80]}")
    else:
        print(" No known vulnerabilities in this version")
    
    print("\n Suggestions:")
    print("   • Safer alternative dhundho (score compare karo)")
    print("   • CI/CD mein integrate karo (GitHub Actions)")
    print("   • Offline mode: --offline")

def main():
    init_db()
    parser = argparse.ArgumentParser(description="Supply Chain Security: Open-Source Security Score")
    parser.add_argument("command", choices=["check"], help="Command")
    parser.add_argument("package", help="Package name")
    parser.add_argument("--ecosystem", default="PyPI", choices=["PyPI", "npm"])
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()

    latest_version = get_latest_version(args.package, args.ecosystem)
    cache_key = latest_version or 'latest'
    
    score, cached_data = get_cached(args.package, args.ecosystem, cache_key)
    if args.offline and score is not None:
        print(" Using cached result (offline mode)")
        print_result(args.package, args.ecosystem, cache_key, score, cached_data.get('vulns', []), cached_data.get('github', {}))
        return

    print(" Fetching real-time security data... (sub-2 sec target)")

    vulns = query_osv(args.package, args.ecosystem, latest_version)

    if args.ecosystem == "PyPI":
        pkg_info = get_pypi_info(args.package)
    else:
        pkg_info = get_npm_info(args.package)

    repo = extract_github_repo(pkg_info, args.ecosystem) if pkg_info else None
    github_info = get_github_metrics(repo) if repo else {}

    score = calculate_score(vulns, github_info)

    cache_data = {'vulns': vulns, 'github': github_info}
    save_cache(args.package, args.ecosystem, cache_key, score, cache_data)

    print_result(args.package, args.ecosystem, latest_version, score, vulns, github_info)

if _name_ == "_main_":
    main()
