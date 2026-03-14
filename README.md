# PhishGuard 🛡️

> Real-time phishing detection tool powered by Machine Learning + Google Safe Browsing + VirusTotal

![Python](https://img.shields.io/badge/Python-3.11-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100-green)
![XGBoost](https://img.shields.io/badge/XGBoost-ML-orange)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-red)

---

## What is PhishGuard?

PhishGuard is a production-grade phishing detection tool that combines machine learning with real-time threat intelligence to identify malicious URLs with high accuracy. Built on Kali Linux, it uses 6 layers of detection to catch phishing attacks that single-method tools miss.

---

## Features

- Machine Learning Model (XGBoost) trained on PhishTank + Tranco datasets
- Google Safe Browsing API integration (same database Chrome uses)
- VirusTotal API integration (70+ antivirus engines)
- PhishTank live database checking
- Domain age verification via WHOIS
- Typosquatting detection (catches fake lookalike domains)
- Brand impersonation detection
- Beautiful web dashboard with light/dark mode
- REST API with batch scanning support
- Scan history and statistics
- Production ready with logging

---

## How It Works

```
URL Input
    ↓
Layer 1: ML Model (XGBoost)
Layer 2: Google Safe Browsing
Layer 3: VirusTotal (70+ engines)
Layer 4: PhishTank Live Check
Layer 5: Domain Age Check
Layer 6: Typosquatting Detection
Layer 7: Brand Impersonation Check
    ↓
Combined Risk Score
    ↓
Verdict: SAFE / PHISHING
```

---

## Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.11 |
| API Framework | FastAPI + Uvicorn |
| ML Model | XGBoost + Scikit-learn |
| URL Parsing | tldextract |
| DNS Lookup | dnspython |
| WHOIS | python-whois |
| Page Scraping | BeautifulSoup4 |
| Data Processing | Pandas + NumPy |
| Threat Intel | Google Safe Browsing + VirusTotal |

---

## Installation

### Requirements
- Python 3.11+
- Kali Linux (or any Linux distro)
- Google Safe Browsing API key (free)
- VirusTotal API key (free)

### Setup

```bash
# Clone the repository
git clone https://github.com/Kalaimathi-1425/phishguard.git
cd phishguard

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create .env file
nano .env
```

Add your API keys to .env:

```
GOOGLE_API_KEY=your_google_safe_browsing_key
VIRUSTOTAL_KEY=your_virustotal_key
```

```bash
# Download datasets
python3 download_data.py

# Train the ML model
python3 train_model.py

# Start the API
uvicorn api:app --host 0.0.0.0 --port 8000
```

---

## Usage

### Web Dashboard

```
Open browser and go to:
http://localhost:8000/dashboard
```

### API

```bash
# Scan single URL
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Scan multiple URLs
curl -X POST http://localhost:8000/scan/batch \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://google.com", "https://suspicious-site.xyz"]}'

# Get scan history
curl http://localhost:8000/history

# Get statistics
curl http://localhost:8000/stats
```

### CLI Scanner

```bash
# Scan single URL
python3 scanner.py https://example.com

# Batch scan from file
python3 scanner.py --batch urls.txt
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | / | API status |
| GET | /dashboard | Web dashboard |
| POST | /scan | Scan single URL |
| POST | /scan/batch | Scan up to 20 URLs |
| GET | /history | Recent scan history |
| GET | /stats | Scan statistics |
| GET | /health | Health check |
| GET | /docs | Interactive API docs |

---

## Example Response

```json
{
  "scan_id": "a1b2c3d4",
  "url": "https://paypal-secure-verify.xyz",
  "verdict": "PHISHING",
  "risk": "HIGH",
  "phishing_probability": 0.9473,
  "live_score": 85,
  "flags": [
    "Google: flagged as SOCIAL_ENGINEERING",
    "VirusTotal: 12 engines flagged",
    "Domain Age: only 3 days old"
  ],
  "features": {
    "url_length": 35,
    "has_https": 1,
    "suspicious_keywords": 3,
    "hyphen_count": 2
  },
  "scanned_at": "2026-01-01T10:00:00"
}
```

---

## Detection Accuracy

| Method | Accuracy |
|---|---|
| ML Model alone | ~85% |
| ML + Domain Age | ~88% |
| ML + Typosquatting | ~91% |
| All 6 layers combined | ~99% |

---

## Project Structure

```
phishguard/
├── api.py                 ← FastAPI REST API
├── live_check.py          ← Live threat intelligence
├── feature_extractor.py   ← URL feature extraction
├── train_model.py         ← ML model training
├── scanner.py             ← CLI scanner
├── download_data.py       ← Dataset downloader
├── dashboard.html         ← Web UI
├── requirements.txt       ← Dependencies
├── Procfile               ← Deployment config
└── .env                   ← API keys (not in repo)
```

---

## Getting API Keys

### Google Safe Browsing (Free)
1. Go to https://console.cloud.google.com
2. Create new project
3. Enable Safe Browsing API
4. Create API key under Credentials

### VirusTotal (Free)
1. Go to https://virustotal.com
2. Create free account
3. Go to profile → API Key
4. Copy your key

---

## Deployment

### Render (Free, No Credit Card)
```bash
# Push to GitHub then:
# 1. Go to render.com
# 2. Connect GitHub repo
# 3. Add environment variables
# 4. Deploy!
```

### Docker
```bash
docker build -t phishguard .
docker run -p 8000:8000 phishguard
```

---

## Screenshots

### Dashboard Dark Mode
- Real-time URL scanning
- Phishing probability bar
- Feature breakdown
- Scan history

### Dashboard Light Mode
- Light/Dark toggle
- Statistics cards
- Risk level indicators

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (git checkout -b feature/AmazingFeature)
3. Commit your changes (git commit -m 'Add AmazingFeature')
4. Push to the branch (git push origin feature/AmazingFeature)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License.

---

## Authors

**Kalaimathi**
- GitHub: [@Kalaimathi-1425](https://github.com/Kalaimathi-1425)
**Manikandan**
- Github: [Manikandan-1425](https://github.com/Manikandan-1425)
---

## Disclaimer

This tool is built for educational and defensive security purposes only.
Use responsibly and only on URLs you have permission to test.

---

## Acknowledgements

- PhishTank for phishing URL dataset
- Tranco for legitimate URL dataset
- Google Safe Browsing API
- VirusTotal API
- FastAPI framework
- XGBoost library

---

⭐ Star this repo if you find it useful!
