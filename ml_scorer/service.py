from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import joblib
import os
import urllib.parse
import re
import json
import psutil
import time
from logging_config import setup_logging

# Configure logging
logger = setup_logging(__name__)

app = FastAPI()
MODEL_PATH = os.getenv("MODEL_PATH", "/app/waf_model.pkl")
model = None

# Stats tracking
request_count = 0
start_time = time.time()

# --- 1. Master Preprocessor ---
def master_preprocess(text):
    if not isinstance(text, str) or not text:
        return ""
    
    decoded = text
    for _ in range(3):
        try:
            temp = urllib.parse.unquote(decoded)
            if temp == decoded: break
            decoded = temp
        except: break
    
    decoded = decoded.lower()
    decoded = re.sub(r'\s+', ' ', decoded).strip()
    return decoded

# --- 2. Deep Payload Parser ---
def dissect_payload(path, body, headers):
    components = {}
    
    # A. Path Analysis
    if path:
        components["URL Full"] = master_preprocess(path)
        try:
            parsed = urllib.parse.urlparse(path)
            if parsed.query:
                components["URL Raw Query"] = master_preprocess(parsed.query)
            segments = parsed.path.strip("/").split("/")
            for i, segment in enumerate(segments):
                if segment:
                    components[f"URL Segment {i+1}"] = master_preprocess(segment)
            query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            for k, values in query_params.items():
                for v in values:
                    components[f"URL Param: {k}"] = master_preprocess(v)
        except:
            pass

    # B. Body Analysis
    if body:
        components["Body Raw"] = master_preprocess(body)
        try:
            json_data = json.loads(body)
            if isinstance(json_data, dict):
                def inspect_json(data, prefix="Body"):
                    for k, v in data.items():
                        if isinstance(v, dict):
                            inspect_json(v, prefix=f"{prefix}.{k}")
                        elif isinstance(v, list):
                            for item in v:
                                if isinstance(item, (str, int, float)):
                                    components[f"{prefix}: {k}[]"] = master_preprocess(str(item))
                        else:
                            components[f"{prefix}: {k}"] = master_preprocess(str(v))
                inspect_json(json_data)
                return components 
        except:
            pass
            
        try:
            form_data = urllib.parse.parse_qs(body, keep_blank_values=True)
            if form_data:
                for k, values in form_data.items():
                    for v in values:
                        components[f"Body Form: {k}"] = master_preprocess(v)
        except:
            pass

    # C. Header Analysis
    if headers:
        for k, v in headers.items():
            key_lower = k.lower()
            
            # 1. Skip standard noisy headers
            if key_lower in ["host", "accept", "connection", "accept-encoding", "accept-language", "content-length", "upgrade-insecure-requests"]:
                continue
            
            # 2. Skip Browser Fingerprinting Headers (Save CPU & reduce noise)
            if key_lower.startswith("sec-ch-ua") or key_lower.startswith("sec-fetch"):
                continue

            # 3. Skip Cache/Priority
            if key_lower in ["priority", "cache-control", "pragma"]:
                continue

            components[f"Header: {k}"] = master_preprocess(v)

    return components

# --- 3. Startup ---
@app.on_event("startup")
def load_model():
    global model
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        logger.info(f"ML Model Loaded: {MODEL_PATH}")
    else:
        logger.error(f"Critical: Model not found at {MODEL_PATH}. Check logs.")

class RequestData(BaseModel):
    path: str
    body: str
    length: int
    headers: dict = {}

# --- 4. Heuristic Scorer (Generic) ---
def calculate_heuristic_score(content):
    # This penalizes (;), ((), etc. Good for Body/SQL, BAD for User-Agents.
    suspicious_chars = {
        "'": 0.15, '"': 0.10, "<": 0.15, ">": 0.15, ";": 0.10, "--": 0.20,
        "(": 0.05, ")": 0.05, "$": 0.10, "`": 0.10, "union": 0.30, "select": 0.20,
        "{": 0.10, "}": 0.10
    }
    score = 0.0
    content_lower = content.lower()
    for char, weight in suspicious_chars.items():
        if char in content_lower:
            score += (weight * content_lower.count(char))
    return min(score, 0.60)


@app.get("/health")
def health_check():
    process = psutil.Process(os.getpid())
    memory_info = process.memory_info()
    memory_mb = round(memory_info.rss / 1024 / 1024, 2)
    cpu_percent = process.cpu_percent(interval=None)
    uptime_min = (time.time() - start_time) / 60
    rpm = int(request_count / uptime_min) if uptime_min > 0 else 0
    
    return {
        "status": "online",
        "cpu": f"{cpu_percent}%",
        "memory": f"{memory_mb} MB",
        "network": f"{rpm} Req/min"
    }

@app.post("/predict")
def predict(data: RequestData):
    global request_count
    request_count += 1
    
    logger.debug("Request #%s - Path: %s", request_count, data.path)

    if not model:
        logger.error("Model not loaded")
        raise HTTPException(status_code=503, detail="Model not loaded")

    inspectable_items = dissect_payload(data.path, data.body, data.headers)
    
    max_risk_score = 0.0
    is_anomaly = False
    detected_type = "Normal"
    trigger_content = "" 

    # --- 5. Hybrid Analysis Loop ---
    for source, content in inspectable_items.items():
        if not content.strip(): continue
        if content.strip() in ["/", "\\"]: continue
        
        # Skip short, safe tokens
        is_short = len(content) < 4
        is_alphanum = content.replace('.', '').replace('-', '').isalnum()
        if is_short and is_alphanum:
            continue

        # A. ML Analysis (Always Run)
        pred_label = model.predict([content])[0]
        probs = model.predict_proba([content])[0]
        ml_confidence = probs[list(model.classes_).index(pred_label)]
        
        if pred_label == "Normal":
            ml_risk = 1.0 - ml_confidence 
        else:
            ml_risk = ml_confidence

        # B. Conditional Heuristic Scoring
        heuristic_boost = 0.0
        
        if "user-agent" in source.lower():
            # 🟢 BYPASS: Do NOT run heuristic scorer on User-Agents.
            # Normal browsers have ";" and "(". 
            # Bad bots are already blocked by Go Rules.
            # We trust the ML model alone for subtle UA anomalies.
            heuristic_boost = 0.0 
        else:
            # 🔴 ENFORCE: Run heuristic scorer on Body/Path.
            # Semicolons here are still suspicious (SQLi).
            heuristic_boost = calculate_heuristic_score(content)

        # C. Final Calculation
        final_risk = ml_risk + heuristic_boost
        if final_risk > 1.0: final_risk = 1.0

        if final_risk > 0.75:
            is_anomaly = True
        
        if final_risk > max_risk_score:
            max_risk_score = final_risk
            trigger_content = content 
            
            if pred_label != "Normal":
                clean_label = pred_label.replace("malicious(", "").replace(")", "").upper()
                detected_type = "ML_" + clean_label 

    return {
        "is_anomaly": is_anomaly,
        "anomaly_score": float(max_risk_score),
        "attack_type": detected_type,
        "trigger_content": trigger_content
    }