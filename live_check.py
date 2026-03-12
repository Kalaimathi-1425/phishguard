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

# ── Master Function ───────────────────────────
def full_live_check(url: str) -> dict:
    url = fix_url(url)

    # Run all checks
    google  = check_google(url)
    vt      = check_virustotal(url)
    pt      = check_phishtank(url)
    age     = check_domain_age(url)
    typo    = check_typosquatting(url)
    brand   = check_brand_impersonation(url)

    # Calculate total score
    score = 0
    flags = []

    if google.get("flagged"):
        score += google.get("score", 0)
        flags.append(f"Google: {google.get('reason')}")

    if vt.get("flagged"):
        score += vt.get("score", 0)
        flags.append(f"VirusTotal: {vt.get('reason')}")

    if pt.get("flagged"):
        score += pt.get("score", 0)
        flags.append(f"PhishTank: {pt.get('reason')}")

    if age.get("flagged"):
        score += age.get("score", 0)
        flags.append(f"Domain Age: {age.get('reason')}")

    if typo.get("flagged"):
        score += typo.get("score", 0)
        flags.append(f"Typosquatting: {typo.get('reason')}")

    if brand.get("flagged"):
        score += brand.get("score", 0)
        flags.append(
            f"Brand Abuse: {brand.get('reason')}")

    score   = min(score, 100)
    prob    = round(score / 100, 4)
    verdict = "PHISHING" if score >= 30 else "SAFE"
    risk    = "HIGH"   if score >= 70 else \
              "MEDIUM" if score >= 30 else "LOW"

    return {
        "url":     url,
        "verdict": verdict,
        "risk":    risk,
        "score":   score,
        "prob":    prob,
        "flags":   flags,
        "checks": {
            "google_safe_browsing": google,
            "virustotal":           vt,
            "phishtank":            pt,
            "domain_age":           age,
            "typosquatting":        typo,
            "brand_impersonation":  brand
        }
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
