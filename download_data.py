import requests, zipfile, os

def download_phishtank():
    url = "http://data.phishtank.com/data/online-valid.csv"
    headers = {"User-Agent": "phishtank/myapp"}
    print("[*] Downloading PhishTank dataset...")
    try:
        r = requests.get(url, headers=headers, timeout=30)
        with open("phishtank.csv", "wb") as f:
            f.write(r.content)
        print("[+] phishtank.csv saved!")
    except Exception as e:
        print(f"[-] Failed: {e}")

def download_tranco():
    url = "https://tranco-list.eu/top-1m.csv.zip"
    print("[*] Downloading Tranco legit URL list...")
    try:
        r = requests.get(url, timeout=60)
        with open("tranco.zip", "wb") as f:
            f.write(r.content)
        with zipfile.ZipFile("tranco.zip", "r") as z:
            z.extractall(".")
        print("[+] top-1m.csv saved!")
    except Exception as e:
        print(f"[-] Failed: {e}")

if __name__ == "__main__":
    download_phishtank()
    download_tranco()
