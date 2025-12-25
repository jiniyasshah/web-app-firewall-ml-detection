#!/bin/sh
if [ ! -f "waf_model.pkl" ]; then
    echo "⚠️ Model not found. Training..."
    python train.py
fi
exec uvicorn service:app --host 0.0.0.0 --port 8000