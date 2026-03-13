from live_check import full_live_check
import os
import uuid
import logging
from datetime import datetime
from typing import List,Optional

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
    model          = joblib.load("phishing_model.pkl")
    feature_columns = joblib.load("feature_columns.pkl")
    columns        = feature_columns
    logger.info("[+] ML model loaded")
    logger.info("[+] Feature columns loaded")
except Exception as e:
    logger.error(f"[-] Model load failed: {e}")
    model          = None
    feature_columns = []
    columns        = []
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

# ── Routes ────────────────────────────────────

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
        raise HTTPException(
            status_code=404,
            detail="dashboard.html not found"
        )
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
async def scan_url(request: ScanRequest):
    url = request.url.strip()
    if not url.startswith("http"):
        url = "https://" + url

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
        score = 85 if path_flags else 40
        verdict = "PHISHING" if path_flags else "UNKNOWN"
        risk = "HIGH" if path_flags else "MEDIUM"
        flags = []
        if path_flags:
            flags.append("Suspicious path keywords found: " + ", ".join(path_flags))
        flags.append("localhost URL cannot be verified by external services")

        return {
            "url": url,
            "verdict": verdict,
            "risk": risk,
            "phishing_probability": round(score / 100, 4),
            "ml_probability": round(score / 100, 4),
            "live_score": score,
            "flags": flags,
            "features": {
                "url_length": len(url),
                "has_https": 1 if url.startswith("https") else 0,
                "hyphen_count": url.count("-"),
                "dot_count": url.count("."),
                "suspicious_keywords": len(path_flags),
                "has_ip": 0,
                "subdomain_depth": 0
            },
            "checks": {
                "google_safe_browsing": {"flagged": None},
                "virustotal": {"flagged": None},
                "phishtank": {"flagged": None},
                "domain_age": {"flagged": None, "age_days": -1},
                "typosquatting": {"flagged": False},
                "brand_impersonation": {"flagged": False}
            }
        }

    # Normal scan for real URLs
    try:
        from feature_extractor import extract_features
        from live_check import full_live_check
        import numpy as np

        features = extract_features(url)
        feature_df = pd.DataFrame([features])
        feature_df = feature_df.reindex(columns=feature_columns, fill_value=0)
        ml_prob = float(model.predict_proba(feature_df)[0][1])

        live_result = full_live_check(url)
        live_score = live_result.get("score", 0)
        flags = live_result.get("flags", [])
        checks = live_result.get("checks", {})

        final_score = (live_score * 0.8) + (ml_prob * 100 * 0.2)
        final_prob = round(min(final_score / 100, 1.0), 4)

        verdict = "PHISHING" if final_prob >= 0.3 else "SAFE"
        risk = "HIGH" if final_prob >= 0.7 else "MEDIUM" if final_prob >= 0.3 else "LOW"

        return {
            "url": url,
            "verdict": verdict,
            "risk": risk,
            "phishing_probability": final_prob,
            "ml_probability": round(ml_prob, 4),
            "live_score": live_score,
            "flags": flags,
            "features": {
                "url_length": features.get("url_length", 0),
                "has_https": features.get("has_https", 0),
                "hyphen_count": features.get("hyphen_count", 0),
                "dot_count": features.get("dot_count", 0),
                "suspicious_keywords": features.get("suspicious_keywords", 0),
                "has_ip": features.get("has_ip", 0),
                "subdomain_depth": features.get("subdomain_depth", 0)
            },
            "checks": checks
        }

    except Exception as e:
        return {
            "url": url,
            "verdict": "ERROR",
            "risk": "UNKNOWN",
            "phishing_probability": 0.0,
            "ml_probability": 0.0,
            "live_score": 0,
            "flags": ["Error during scan: " + str(e)],
            "features": {},
            "checks": {}
        }
def scan_url(data: URLInput):
    url = fix_url(data.url)

    if not url:
        raise HTTPException(
            status_code=400,
            detail="URL cannot be empty"
        )

    logger.info(f"Scanning: {url}")

    try:
        # ── Step 1: ML model ──────────────────
        ml_prob = run_ml(url)

        # ── Step 2: Live checks ───────────────
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

        # ── Step 3: Combine both scores ───────
        ml_score    = ml_prob * 100
        final_score = (l_score * 0.8) + (ml_score * 0.2)
        final_prob  = round(final_score / 100, 4)

        # ── Step 4: Final verdict ─────────────
        if final_score >= 70:
            verdict = "PHISHING"
            risk    = "HIGH"
        elif final_score >= 30:
            verdict = "PHISHING"
            risk    = "MEDIUM"
        else:
            verdict = "SAFE"
            risk    = "LOW"

        # ── Step 5: Get features ──────────────
        try:
            features = extract_features(url)
        except Exception:
            features = {}

        # ── Step 6: Build result ──────────────
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

        # ── Step 7: Save to history ───────────
        scan_history.insert(0, {
            "scan_id":     scan_id,
            "url":         url,
            "verdict":     verdict,
            "risk":        risk,
            "probability": final_prob,
            "scanned_at":  datetime.now().isoformat()
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
        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {str(e)}"
        )

@app.post("/scan/batch")
def scan_batch(data: BatchInput):
    if not data.urls:
        raise HTTPException(
            status_code=400,
            detail="URL list cannot be empty"
        )
    if len(data.urls) > 20:
        raise HTTPException(
            status_code=400,
            detail="Maximum 20 URLs per batch"
        )

    results = []
    for url in data.urls:
        try:
            result = scan_url(URLInput(url=url))
            results.append(result)
        except Exception as e:
            results.append({
                "url":     url,
                "verdict": "ERROR",
                "error":   str(e)
            })

    return {
        "total":    len(results),
        "phishing": sum(1 for r in results
                        if r.get("verdict") == "PHISHING"),
        "safe":     sum(1 for r in results
                        if r.get("verdict") == "SAFE"),
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
    phishing = sum(1 for s in scan_history
                   if s["verdict"] == "PHISHING")
    safe     = sum(1 for s in scan_history
                   if s["verdict"] == "SAFE")

    return {
        "total_scans":    total,
        "total_phishing": phishing,
        "total_safe":     safe,
        "phishing_rate":  f"{(phishing/total*100):.1f}%",
        "risk_breakdown": {
            "high":   sum(1 for s in scan_history
                          if s.get("risk") == "HIGH"),
            "medium": sum(1 for s in scan_history
                          if s.get("risk") == "MEDIUM"),
            "low":    sum(1 for s in scan_history
                          if s.get("risk") == "LOW")
        },
        "last_scan": scan_history[0]["scanned_at"]
    }

@app.delete("/history")
def clear_history():
    scan_history.clear()
    return {"message": "History cleared"}

@app.exception_handler(Exception)
async def global_exception_handler(
    request: Request,
    exc: Exception
):
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
