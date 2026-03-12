#!/usr/bin/env python3
import sys, joblib, pandas as pd
from colorama import Fore, Style, init
from feature_extractor import extract_features

init(autoreset=True)

try:
    model   = joblib.load("phishing_model.pkl")
    columns = joblib.load("feature_columns.pkl")
except:
    print("[-] Model not found. Run: python3 train_model.py first!")
    sys.exit(1)

def risk_color(risk):
    return Fore.RED if risk == "HIGH" else Fore.YELLOW if risk == "MEDIUM" else Fore.GREEN

def scan(url):
if not url.startswith("http://") and \
       not url.startswith("https://"):
        url = "https://" + url

    print(f"\n{Style.BRIGHT}{'='*55}")
    print(f"  🔍 Scanning: {url}")
    print(f"{'='*55}")

    features = extract_features(url)
    df = pd.DataFrame([features]).reindex(columns=columns, fill_value=-1)

    prob  = model.predict_proba(df)[0][1]
    pred  = model.predict(df)[0]
    risk  = "HIGH" if prob > 0.7 else "MEDIUM" if prob > 0.4 else "LOW"
    color = risk_color(risk)

    print(f"\n  Phishing Probability : {prob:.2%}")
    print(f"  Risk Level           : {color}{risk}")
    print(f"  Verdict              : {Fore.RED + '⚠  PHISHING' if pred == 1 else Fore.GREEN + '✓  LIKELY SAFE'}")

    print(f"\n{Style.BRIGHT}  Key Features:")
    print(f"  {'Feature':<28} {'Value'}")
    print(f"  {'-'*40}")
    for k, v in features.items():
        if v not in [-1, 0, ""] and v is not None:
            print(f"  {k:<28} {v}")

    print(f"\n{'='*55}\n")
    return {"url": url, "probability": prob, "verdict": "PHISHING" if pred else "SAFE"}

def batch_scan(filepath):
    print(f"[*] Batch scanning from {filepath}")
    with open(filepath) as f:
        urls = [line.strip() for line in f if line.strip()]
    results = []
    for url in urls:
        r = scan(url)
        results.append(r)
    pd.DataFrame(results).to_csv("scan_results.csv", index=False)
    print(f"[+] Results saved to scan_results.csv")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"\nUsage:")
        print(f"  Single URL : python3 scanner.py https://example.com")
        print(f"  Batch scan : python3 scanner.py --batch urls.txt\n")
    elif sys.argv[1] == "--batch":
        batch_scan(sys.argv[2])
    else:
        scan(sys.argv[1])
