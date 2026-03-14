from live_check import full_live_check
import os
import uuid
import logging
from datetime import datetime
from typing import List, Optional
import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from feature_extractor import extract_features

class ScanRequest(BaseModel):
    url: str

class BatchScanRequest(BaseModel):
    urls: List[str]

# ── Logging ───────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("phishguard.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ── Load ML model ─────────────────────────────
try:
    model           = joblib.load("phishing_model.pkl")
    feature_columns = joblib.load("feature_columns.pkl")
    columns         = feature_columns
    logger.info("[+] ML model loaded")
    logger.info("[+] Feature columns loaded")
except Exception as e:
    logger.error(f"[-] Model load failed: {e}")
    model           = None
    feature_columns = []
    columns         = []

# ── Scan history ──────────────────────────────
scan_history = []
MAX_HISTORY  = 1000

# ── App ───────────────────────────────────────
app = FastAPI(
    title       = "PhishGuard API",
    description = "Phishing detection API",
    version     = "2.0.0"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["*"],
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# ── Models ────────────────────────────────────
class URLInput(BaseModel):
    url: str

class BatchInput(BaseModel):
    urls: List[str]

# ── Helpers ───────────────────────────────────
def fix_url(url: str) -> str:
    url = url.strip()
    if not url.startswith("http://") and \
       not url.startswith("https://"):
        url = "https://" + url
    return url

def run_ml(url: str) -> float:
    if model is None:
        return 0.5
    try:
        features = extract_features(url)
        df = pd.DataFrame([features]).reindex(
            columns=columns, fill_value=-1)
        return float(model.predict_proba(df)[0][1])
    except Exception as e:
        logger.warning(f"ML error: {e}")
        return 0.5

def get_verdict(prob: float):
    risk    = "HIGH"   if prob >= 0.7 else \
              "MEDIUM" if prob >= 0.4 else "LOW"
    verdict = "PHISHING" if prob >= 0.5 else "SAFE"
    return verdict, risk

# ── Core scan logic (shared by single + batch) ─
def process_scan(url: str) -> dict:
    url = fix_url(url)
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    logger.info(f"Scanning: {url}")

    # localhost check
    local_indicators = ["localhost", "127.0.0.1", "0.0.0.0"]
    sus_paths = [
        "microphone", "camera", "password", "login",
        "verify", "credential", "phish", "hack",
        "steal", "capture", "keylog", "payload", "shell"
    ]
    is_local = any(x in url for x in local_indicators)

    if is_local:
        path_flags = [p for p in sus_paths if p in url.lower()]
        score   = 85 if path_flags else 40
        verdict = "PHISHING" if path_flags else "UNKNOWN"
        risk    = "HIGH" if path_flags else "MEDIUM"
        flags   = []
        if path_flags:
            flags.append("Suspicious path keywords found: " + ", ".join(path_flags))
        flags.append("localhost URL cannot be verified by external services")
        flags.append("Local phishing kits often use paths like /microphone /login /verify")

        scan_id = str(uuid.uuid4())[:8]
        result  = {
            "scan_id":              scan_id,
            "url":                  url,
            "verdict":              verdict,
            "risk":                 risk,
            "phishing_probability": round(score / 100, 4),
            "ml_probability":       round(score / 100, 4),
            "live_score":           score,
            "flags":                flags,
            "features": {
                "url_length":          len(url),
                "has_https":           1 if url.startswith("https") else 0,
                "hyphen_count":        url.count("-"),
                "dot_count":           url.count("."),
                "suspicious_keywords": len(path_flags),
                "has_ip":              0,
                "subdomain_depth":     0
            },
            "checks": {
                "google_safe_browsing": {"flagged": None},
                "virustotal":           {"flagged": None},
                "phishtank":            {"flagged": None},
                "domain_age":           {"flagged": None, "age_days": -1},
                "typosquatting":        {"flagged": False},
                "brand_impersonation":  {"flagged": False}
            },
            "scanned_at": datetime.now().isoformat()
        }

        scan_history.insert(0, {
            "scan_id":    scan_id,
            "url":        url,
            "verdict":    verdict,
            "risk":       risk,
            "probability": round(score / 100, 4),
            "scanned_at": datetime.now().isoformat()
        })
        if len(scan_history) > MAX_HISTORY:
            scan_history.pop()

        return result

    # Normal scan for real URLs
    try:
        ml_prob = run_ml(url)

        try:
            live    = full_live_check(url)
            l_score = live["score"]
            flags   = live.get("flags", [])
            checks  = live.get("checks", {})
        except Exception as e:
            logger.warning(f"Live check failed: {e}")
            l_score = 0
            flags   = []
            checks  = {}

        ml_score    = ml_prob * 100
        final_score = (l_score * 0.8) + (ml_score * 0.2)
        final_prob  = round(min(final_score / 100, 1.0), 4)

        # If ML is very confident alone → flag it
        if ml_prob >= 0.85:
            final_prob = round(max(final_prob, ml_prob), 4)
            verdict    = "PHISHING"
            risk       = "HIGH"
        elif final_score >= 70:
            verdict = "PHISHING"
            risk    = "HIGH"
        elif final_score >= 30:
            verdict = "PHISHING"
            risk    = "MEDIUM"
        else:
            # Extra check for suspicious TLDs
            sus_tlds = [".xyz", ".tk", ".ml", ".ga", ".cf", ".top", ".online"]
            if any(t in url for t in sus_tlds):
                verdict = "PHISHING"
                risk    = "MEDIUM"
            else:
                verdict = "SAFE"
                risk    = "LOW"
        try:
            features = extract_features(url)
        except Exception:
            features = {}

        scan_id = str(uuid.uuid4())[:8]
        result  = {
            "scan_id":              scan_id,
            "url":                  url,
            "verdict":              verdict,
            "risk":                 risk,
            "phishing_probability": final_prob,
            "ml_probability":       round(ml_prob, 4),
            "live_score":           l_score,
            "flags":                flags,
            "features":             features,
            "checks":               checks,
            "scanned_at":           datetime.now().isoformat()
        }

        scan_history.insert(0, {
            "scan_id":    scan_id,
            "url":        url,
            "verdict":    verdict,
            "risk":       risk,
            "probability": final_prob,
            "scanned_at": datetime.now().isoformat()
        })
        if len(scan_history) > MAX_HISTORY:
            scan_history.pop()

        logger.info(
            f"Result: {verdict} | "
            f"Risk: {risk} | "
            f"Score: {final_score:.1f} | "
            f"Prob: {final_prob:.2%}"
        )
        return result

    except Exception as e:
        logger.error(f"Scan error: {e}")
        return {
            "url":                  url,
            "verdict":              "ERROR",
            "risk":                 "UNKNOWN",
            "phishing_probability": 0.0,
            "ml_probability":       0.0,
            "live_score":           0,
            "flags":                ["Error during scan: " + str(e)],
            "features":             {},
            "checks":               {}
        }

@app.get("/")
def home():
    return {
        "name":        "PhishGuard API",
        "version":     "2.0.0",
        "status":      "running",
        "total_scans": len(scan_history),
        "endpoints": {
            "scan":      "POST /scan",
            "batch":     "POST /scan/batch",
            "history":   "GET  /history",
            "stats":     "GET  /stats",
            "dashboard": "GET  /dashboard",
            "docs":      "GET  /docs"
        }
    }

@app.get("/dashboard")
def dashboard():
    if not os.path.exists("dashboard.html"):
        raise HTTPException(status_code=404, detail="dashboard.html not found")
    return FileResponse("dashboard.html")

@app.get("/health")
def health():
    return {
        "status":       "healthy",
        "model_loaded": model is not None,
        "total_scans":  len(scan_history),
        "timestamp":    datetime.now().isoformat()
    }

@app.post("/scan")
def scan_url(request: ScanRequest):
    return process_scan(request.url)

@app.post("/scan/batch")
def scan_batch(request: BatchScanRequest):
    if not request.urls:
        return {"error": "No URLs provided", "results": []}

    urls    = request.urls[:20]
    results = []

    for url in urls:
        try:
            result = process_scan(url)
            results.append(result)
        except Exception as e:
            results.append({
                "url":                  url,
                "verdict":              "ERROR",
                "risk":                 "UNKNOWN",
                "phishing_probability": 0.0,
                "flags":                ["Error: " + str(e)],
                "features":             {},
                "checks":               {}
            })

    total    = len(results)
    phishing = sum(1 for r in results if r["verdict"] == "PHISHING")
    safe     = sum(1 for r in results if r["verdict"] == "SAFE")

    return {
        "total":    total,
        "phishing": phishing,
        "safe":     safe,
        "results":  results
    }

@app.get("/history")
def get_history(limit: int = 50):
    limit = min(limit, MAX_HISTORY)
    return {
        "total":   len(scan_history),
        "showing": min(limit, len(scan_history)),
        "scans":   scan_history[:limit]
    }

@app.get("/stats")
def get_stats():
    if not scan_history:
        return {
            "total_scans":    0,
            "total_phishing": 0,
            "total_safe":     0,
            "phishing_rate":  "0%"
        }
    total    = len(scan_history)
    phishing = sum(1 for s in scan_history if s["verdict"] == "PHISHING")
    safe     = sum(1 for s in scan_history if s["verdict"] == "SAFE")
    return {
        "total_scans":    total,
        "total_phishing": phishing,
        "total_safe":     safe,
        "phishing_rate":  f"{(phishing/total*100):.1f}%",
        "risk_breakdown": {
            "high":   sum(1 for s in scan_history if s.get("risk") == "HIGH"),
            "medium": sum(1 for s in scan_history if s.get("risk") == "MEDIUM"),
            "low":    sum(1 for s in scan_history if s.get("risk") == "LOW")
        },
        "last_scan": scan_history[0]["scanned_at"]
    }

@app.delete("/history")
def clear_history():
    scan_history.clear()
    return {"message": "History cleared"}

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "error":  "Internal server error",
            "detail": str(exc)
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api:app",
        host      = "0.0.0.0",
        port      = int(os.getenv("PORT", 8000)),
        reload    = False,
        log_level = "info"
    )
