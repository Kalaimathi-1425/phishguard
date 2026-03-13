import os
import requests
import tldextract
from datetime import datetime
from difflib import SequenceMatcher
from dotenv import load_dotenv

load_dotenv()

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY")

BRANDS = [
    "google", "paypal", "amazon", "facebook",
    "apple", "microsoft", "netflix", "instagram",
    "twitter", "linkedin", "chase", "bankofamerica",
    "wellsfargo", "youtube", "yahoo", "dropbox",
    "github", "adobe", "ebay", "walmart"
]

# ── Fix URL ───────────────────────────────────
def fix_url(url: str) -> str:
    url = url.strip()
    if not url.startswith("http://") and \
       not url.startswith("https://"):
        url = "https://" + url
    return url

# ── Check 1: Google Safe Browsing ─────────────
def check_google(url: str) -> dict:
    try:
        endpoint = (
            "https://safebrowsing.googleapis.com"
            f"/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        )
        payload = {
            "client": {
                "clientId":      "phishguard",
                "clientVersion": "2.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes":    ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":    [{"url": url}]
            }
        }
        r    = requests.post(
            endpoint, json=payload, timeout=5)
        data = r.json()

        if "matches" in data and data["matches"]:
            threat = data["matches"][0]["threatType"]
            return {
                "flagged": True,
                "reason":  f"Google flagged as {threat}",
                "source":  "Google Safe Browsing",
                "score":   100
            }
        return {
            "flagged": False,
            "reason":  "Clean",
            "source":  "Google Safe Browsing",
            "score":   0
        }
    except Exception as e:
        return {
            "flagged": None,
            "source":  "Google Safe Browsing",
            "error":   str(e),
            "score":   0
        }

# ── Check 2: VirusTotal ───────────────────────
def check_virustotal(url: str) -> dict:
    try:
        import base64
        url_id  = base64.urlsafe_b64encode(
            url.encode()).decode().strip("=")
        headers = {"x-apikey": VIRUSTOTAL_KEY}

        r    = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10
        )
        data  = r.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious  = stats.get("malicious",  0)
        suspicious = stats.get("suspicious", 0)
        total      = malicious + suspicious

        return {
            "flagged":   total > 0,
            "malicious": malicious,
            "suspicious": suspicious,
            "reason":    f"{total} engines flagged" \
                         if total > 0 else "Clean",
            "source":    "VirusTotal",
            "score":     min(total * 10, 80)
        }
    except Exception as e:
        return {
            "flagged": None,
            "source":  "VirusTotal",
            "error":   str(e),
            "score":   0
        }

# ── Check 3: PhishTank ────────────────────────
def check_phishtank(url: str) -> dict:
    try:
        r = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={
                "url":    url,
                "format": "json"
            },
            headers={"User-Agent": "phishtank/phishguard"},
            timeout=5
        )
        data  = r.json()
        in_db = data.get(
            "results", {}).get("in_database", False)
        valid = data.get(
            "results", {}).get("valid", False)

        return {
            "flagged": in_db and valid,
            "reason":  "Confirmed phishing" \
                       if (in_db and valid) \
                       else "Not in database",
            "source":  "PhishTank",
            "score":   90 if (in_db and valid) else 0
        }
    except Exception as e:
        return {
            "flagged": None,
            "source":  "PhishTank",
            "error":   str(e),
            "score":   0
        }

# ── Check 4: Domain Age ───────────────────────
def check_domain_age(url: str) -> dict:
    try:
        import whois
        domain  = tldextract.extract(url).registered_domain
        w       = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        age = (datetime.now() - created).days

        return {
            "flagged":  age < 30,
            "age_days": age,
            "reason":   f"Domain only {age} days old" \
                        if age < 30 \
                        else f"Domain is {age} days old",
            "source":   "Domain Age Check",
            "score":    30 if age < 30 else 0
        }
    except Exception as e:
        return {
            "flagged": None,
            "source":  "Domain Age",
            "error":   str(e),
            "score":   0
        }

# ── Check 5: Typosquatting ────────────────────
def check_typosquatting(url: str) -> dict:
    try:
        ext    = tldextract.extract(url)
        domain = ext.domain.lower()

        for brand in BRANDS:
            ratio = SequenceMatcher(
                None, domain, brand).ratio()
            if 0.75 < ratio < 1.0:
                return {
                    "flagged": True,
                    "reason":  f"'{domain}' looks like '{brand}'",
                    "source":  "Typosquatting Detection",
                    "score":   50
                }
        return {
            "flagged": False,
            "reason":  "No typosquatting detected",
            "source":  "Typosquatting Detection",
            "score":   0
        }
    except Exception as e:
        return {
            "flagged": None,
            "source":  "Typosquatting",
            "error":   str(e),
            "score":   0
        }

# ── Check 6: Brand Impersonation ──────────────
def check_brand_impersonation(url: str) -> dict:
    try:
        ext       = tldextract.extract(url)
        subdomain = (ext.subdomain or "").lower()
        domain    = (ext.domain   or "").lower()

        for brand in BRANDS:
            if brand in subdomain and \
               brand not in domain:
                return {
                    "flagged": True,
                    "reason":  f"'{brand}' abused in subdomain",
                    "source":  "Brand Impersonation",
                    "score":   60
                }
        return {
            "flagged": False,
            "reason":  "No brand impersonation",
            "source":  "Brand Impersonation",
            "score":   0
        }
    except Exception as e:
        return {
            "flagged": None,
            "source":  "Brand Impersonation",
            "error":   str(e),
            "score":   0
        }

def full_live_check(url: str) -> dict:
    url = fix_url(url)
    
    # ── Localhost / local IP detection ──────────────────
    local_indicators = [
        "localhost", "127.0.0.1",
        "0.0.0.0", "192.168.", "10.0.", "172.16."
    ]
    
    sus_paths = [
        "microphone", "camera", "password",
        "login", "verify", "credential",
        "phish", "hack", "steal", "capture",
        "keylog", "hook", "payload", "shell",
        "exploit", "inject", "attack", "index"
    ]
    
    is_local = any(x in url for x in local_indicators)
    
    if is_local:
        path_flags = [p for p in sus_paths if p in url.lower()]
        
        score = 85 if path_flags else 40
        
        flags = ["localhost URL — external checks not available"]
        
        if path_flags:
            flags.append("Suspicious path keywords: " + ", ".join(path_flags))
            flags.append("Local phishing kits often use paths like /microphone /login /verify")
        else:
            flags.append("Manually verify this URL before trusting it")
        
        return {
            "score":   score,
            "verdict": "SUSPICIOUS" if path_flags else "UNKNOWN",
            "flags":   flags,
            "checks": {
                "google_safe_browsing":  {"flagged": None, "note": "N/A - localhost"},
                "virustotal":            {"flagged": None, "note": "N/A - localhost"},
                "phishtank":             {"flagged": None, "note": "N/A - localhost"},
                "domain_age":            {"flagged": None, "age_days": -1},
                "typosquatting":         {"flagged": False},
                "brand_impersonation":   {"flagged": False}
            }
        }
    
    # ── Normal live checks (existing code below) ────────
    results = {}
    flags   = []
    score   = 0

    g = check_google(url)
    results["google_safe_browsing"] = g
    if g.get("flagged"):
        score += 100
        flags.append("Google Safe Browsing: flagged as " + str(g.get("threat_type", "PHISHING")))

    v = check_virustotal(url)
    results["virustotal"] = v
    if v.get("flagged"):
        mal = v.get("malicious", 0)
        score += min(mal * 10, 80)
        flags.append("VirusTotal: " + str(mal) + " engines flagged this URL")

    p = check_phishtank(url)
    results["phishtank"] = p
    if p.get("flagged"):
        score += 90
        flags.append("PhishTank: confirmed phishing URL")

    d = check_domain_age(url)
    results["domain_age"] = d
    if d.get("flagged"):
        age = d.get("age_days", 0)
        score += 30
        flags.append("Domain Age: only " + str(age) + " days old — very new domain")

    t = check_typosquatting(url)
    results["typosquatting"] = t
    if t.get("flagged"):
        score += 50
        flags.append("Typosquatting: looks like a fake lookalike domain")

    b = check_brand_impersonation(url)
    results["brand_impersonation"] = b
    if b.get("flagged"):
        score += 60
        flags.append("Brand Impersonation: brand name used in suspicious domain")

    score = min(score, 100)

    verdict = "PHISHING" if score >= 30 else "SAFE"

    return {
        "score":   score,
        "verdict": verdict,
        "flags":   flags,
        "checks":  results
    }

# ── Run from terminal ─────────────────────────
if __name__ == "__main__":
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 \
          else input("Enter URL: ")
    result = full_live_check(url)

    print("\n" + "="*50)
    print("  URL     : " + result["url"])
    print("  VERDICT : " + result["verdict"])
    print("  RISK    : " + result["risk"])
    print("  SCORE   : " + str(result["score"]) + "/100")

    if result["flags"]:
        print("\n  FLAGS DETECTED:")
        for f in result["flags"]:
            print("    WARNING: " + f)
    else:
        print("\n  No threats detected")

    print("="*50 + "\n")
