# feature_extractor.py (Fast Version - No page fetching)
import re
import math
import warnings
from collections import Counter
from urllib.parse import urlparse
from datetime import datetime

import tldextract

def check_brand_impersonation(url):
    ext = tldextract.extract(url)
    subdomain = ext.subdomain.lower()
    domain    = ext.domain.lower()

    BRANDS = [
        "paypal", "google", "amazon", "apple",
        "microsoft", "facebook", "netflix", "chase",
        "bankofamerica", "instagram", "twitter"
    ]

    for brand in BRANDS:
        if brand in subdomain and brand not in domain:
            return 1   
    return 0

warnings.filterwarnings("ignore")

SUSPICIOUS_WORDS = [
    "login", "secure", "verify", "update", "banking",
    "account", "confirm", "password", "signin", "free",
    "lucky", "bonus", "click", "winner", "urgent",
    "suspend", "limited", "validate", "recover", "unlock"
]

TRUSTED_DOMAINS = [
    "google.com", "youtube.com", "facebook.com",
    "amazon.com", "microsoft.com", "apple.com",
    "paypal.com", "twitter.com", "instagram.com"
]

def get_domain_age(domain):
    try:
        import whois
        from datetime import datetime
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        age = (datetime.now() - creation).days
        return age
    except:
        return -1  
def extract_features(url):

    if not url.startswith("http://") and \
       not url.startswith("https://"):
        url = "https://" + url

    f = {}

def calculate_entropy(s):
    if not s:
        return 0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total)
                for c in counts.values())

def extract_features(url):
    f = {}

    try:
        parsed = urlparse(url)
        ext    = tldextract.extract(url)
        domain = ext.registered_domain or parsed.netloc
        path   = parsed.path or ""

        # ── Lexical features ─────────────────────────
        f["url_length"]          = len(url)
        f["has_ip"]              = 1 if re.match(
            r'https?://\d+\.\d+\.\d+\.\d+', url) else 0
        f["has_at"]              = 1 if "@" in url else 0
        f["has_double_slash"]    = 1 if "//" in url[8:] else 0
        f["hyphen_count"]        = url.count("-")
        f["dot_count"]           = url.count(".")
        f["has_https"]           = 1 if url.startswith("https") else 0
        f["subdomain_depth"]     = len(
            ext.subdomain.split(".")) if ext.subdomain else 0
        f["url_entropy"]         = round(calculate_entropy(url), 4)
        f["digit_count"]         = sum(c.isdigit() for c in url)
        f["special_chars"]       = len(
            re.findall(r'[!$%^&*()+={}\[\];\'\":|<>?]', url))
        f["suspicious_keywords"] = sum(
            w in url.lower() for w in SUSPICIOUS_WORDS)
        f["domain_length"]       = len(domain)
        f["path_length"]         = len(path)
        f["num_params"]          = len(
            parsed.query.split("&")) if parsed.query else 0
        f["has_port"]            = 1 if parsed.port else 0
        f["path_depth"]          = path.count("/")
        f["has_fragment"]        = 1 if parsed.fragment else 0
        f["domain_entropy"]      = round(calculate_entropy(domain), 4)
        f["is_trusted_domain"]   = 1 if domain in TRUSTED_DOMAINS else 0

        # ── TLD features ─────────────────────────────
        suspicious_tlds = [
            ".xyz", ".top", ".club", ".online",
            ".site", ".tk", ".ml", ".ga", ".cf"
        ]
        f["suspicious_tld"] = 1 if any(
            url.lower().endswith(t) for t in suspicious_tlds) else 0

        # ── Domain pattern features ───────────────────
        f["has_brand_in_subdomain"] = 1 if any(
            brand in (ext.subdomain or "").lower()
            for brand in ["paypal", "google", "amazon",
                          "apple", "microsoft", "bank"]
        ) else 0

        f["num_subdomains"] = len(
            ext.subdomain.split(".")) if ext.subdomain else 0
        f["domain_has_numbers"] = 1 if re.search(
            r'\d', domain) else 0
        f["url_has_redirect"] = 1 if "redirect" in url.lower() \
            or "url=" in url.lower() else 0

    except Exception:
        # Return default values if anything fails
        f = {k: -1 for k in [
            "url_length", "has_ip", "has_at",
            "has_double_slash", "hyphen_count", "dot_count",
            "has_https", "subdomain_depth", "url_entropy",
            "digit_count", "special_chars", "suspicious_keywords",
            "domain_length", "path_length", "num_params",
            "has_port", "path_depth", "has_fragment",
            "domain_entropy", "is_trusted_domain",
            "suspicious_tld", "has_brand_in_subdomain",
            "num_subdomains", "domain_has_numbers",
            "url_has_redirect"
        ]}

    return f
