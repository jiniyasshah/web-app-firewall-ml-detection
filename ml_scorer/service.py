from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import os
import urllib.parse
import re
import json

app = FastAPI()
MODEL_PATH = "waf_model.pkl"
model = None

# --- 1. Master Preprocessor (Must match train_model.py) ---
def master_preprocess(text):
    if not isinstance(text, str) or not text:
        return ""
    
    # A. Recursive Decode
    decoded = text
    for _ in range(3):
        try:
            temp = urllib.parse.unquote(decoded)
            if temp == decoded: break
            decoded = temp
        except: break
    
    # B. Lowercase
    decoded = decoded.lower()
    
    # C. Space Canonicalization
    decoded = re.sub(r'\s+', ' ', decoded).strip()
    
    return decoded

# --- 2. Deep Payload Parser ---
def dissect_payload(path, body):
    """
    Breaks down the Path and Body into inspectable components.
    """
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

    return components

@app.on_event("startup")
def load_model():
    global model
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        print(f"✅ ML Model Loaded: {MODEL_PATH}")
    else:
        print(f"⚠️ Model not found at {MODEL_PATH}. Prediction will fail.")

class RequestData(BaseModel):
    path: str
    body: str
    length: int

# --- 3. New Helper: Calculate Heuristic Boost ---
def calculate_heuristic_score(content):
    """
    Returns a float (0.0 to 0.5) representing how 'sketchy' the string looks
    based on character density.
    """
    # 1. The 'Bad List'
    suspicious_chars = {
        "'": 0.15,   # High risk (SQLi)
        '"': 0.10,   # Medium risk (JSON/SQLi)
        "<": 0.15,   # High risk (XSS)
        ">": 0.15,   # High risk (XSS)
        ";": 0.10,   # Command Injection
        "--": 0.20,  # Comment bypass (Critical)
        "(": 0.05,   # Function calls
        ")": 0.05,
        "$": 0.10,   # Variables
        "`": 0.10,   # Shell exec
        "union": 0.30, # Keywords (Bonus)
        "select": 0.20,
        "sleep": 0.20
    }
    
    score = 0.0
    content_lower = content.lower()
    
    # 2. Iterate and Sum
    for char, weight in suspicious_chars.items():
        count = content_lower.count(char)
        if count > 0:
            # We add weight * count, but diminish returns for repeated chars to prevent explosion
            # e.g. 5 single quotes shouldn't give 5x score, maybe 2.5x
            added_score = (weight * count) 
            score += added_score

    # 3. Cap the heuristic boost at 0.60 (So it can't purely decide on its own unless extreme)
    return min(score, 0.60)

@app.post("/predict")
def predict(data: RequestData):
    if not model:
        raise HTTPException(status_code=503, detail="Model not loaded")

    inspectable_items = dissect_payload(data.path, data.body)
    
    max_risk_score = 0.0
    is_anomaly = False
    
    # --- 4. Hybrid Analysis Loop ---
    for source, content in inspectable_items.items():
        if not content.strip(): 
            continue
            
        # Filter: Skip short/safe
        is_short = len(content) < 4
        is_alphanum = content.replace('.', '').isalnum()
        if is_short and is_alphanum:
            continue

        # A. Get ML Confidence
        pred_label = model.predict([content])[0]
        probs = model.predict_proba([content])[0]
        ml_confidence = probs[list(model.classes_).index(pred_label)]
        
        # Normalize ML Score: If pred is "Normal", risk is (1 - confidence). 
        # If pred is "Attack", risk is confidence.
        if pred_label == "Normal":
            ml_risk = 1.0 - ml_confidence 
        else:
            ml_risk = ml_confidence

        # B. Get Heuristic Boost
        heuristic_boost = calculate_heuristic_score(content)
        
        # C. Calculate Final Hybrid Score
        # Formula: Base ML + Heuristic Boost
        final_risk = ml_risk + heuristic_boost
        
        # Cap at 1.0
        if final_risk > 1.0: final_risk = 1.0

        # D. Threshold Logic
        # If final risk > 0.75, we consider it an attack
        if final_risk > 0.75:
            is_anomaly = True
        
        # Track max score for reporting
        if final_risk > max_risk_score:
            max_risk_score = final_risk

    return {
        "is_anomaly": is_anomaly,
        "anomaly_score": float(max_risk_score)
    }