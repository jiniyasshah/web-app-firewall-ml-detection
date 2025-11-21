from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import pandas as pd
import os
import sys

# --- HELPERS ---
# Must match train.py exactly
def get_body(df): return df['body']

# Inception Hack
import __main__
__main__.get_body = get_body
# ----------------

app = FastAPI()
MODEL_PATH = "model/waf_model.joblib"
model = None

@app.on_event("startup")
def load_model():
    global model
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        print("ML Model Loaded Successfully.")

class RequestData(BaseModel):
    path: str
    body: str
    length: int

@app.post("/predict")
def predict(data: RequestData):
    if not model:
        raise HTTPException(status_code=503, detail="Model not loaded")

    df_input = pd.DataFrame([data.dict()])
    
    # Predict
    # Class 0 = Safe, Class 1 = Attack
    prediction_class = model.predict(df_input)[0]
    confidence = model.predict_proba(df_input)[0][1] # Probability of Attack

    is_anomaly = True if prediction_class == 1 else False

    return {
        "is_anomaly": is_anomaly,
        "anomaly_score": float(confidence)
    }