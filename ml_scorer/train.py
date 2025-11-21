import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import FunctionTransformer
import joblib
import os
import random

print("Generating DEMO-OPTIMIZED training data (Final Version)...")

# --- 1. GENERATE GOOD TRAFFIC (Label = 0) ---
def generate_good_data(n_samples=5000):
    paths = []
    bodies = []
    
    safe_values = ["jim", "jane", "admin_user", "guest", "iphone", "search_term", "12345", "true", "false", "active"]
    safe_keys = ["user", "username", "id", "q", "query", "token", "action", "email"]
    
    base_paths = ['/login', '/home', '/search', '/api/order', '/contact', '/submit']

    for _ in range(n_samples):
        path = random.choice(base_paths)
        
        # RANDOMIZE: 30% Empty Body (GET), 70% JSON Body (POST)
        if random.random() < 0.30:
            body = "" # Teach model that empty is OK!
        else:
            key = random.choice(safe_keys)
            val = random.choice(safe_values)
            if random.random() > 0.5:
                 body = f'{{"{key}": "{val}"}}'
            else:
                 body = f'{{"{key}": "{val}", "id": {random.randint(1,999)}}}'
        
        paths.append(path)
        bodies.append(body)
    
    return pd.DataFrame({'path': paths, 'body': bodies, 'label': 0})

# --- 2. GENERATE BAD TRAFFIC (Label = 1) ---
def generate_bad_data(n_samples=5000):
    paths = []
    bodies = []
    
    attacks = [
        "UNION SELECT * FROM", "OR 1=1", "1' OR '1'='1", "DROP TABLE",
        "<script>alert(1)</script>", "javascript:void(0)",
        "../../etc/passwd", "/bin/bash", "cat /etc/shadow",
        "${jndi:ldap://}", "class.module.classLoader"
    ]
    
    for _ in range(n_samples):
        attack = random.choice(attacks)
        
        # 1. Attack in Body (JSON wrapper)
        if random.random() > 0.5:
            path = "/api/submit"
            body = f'{{"user": "{attack}"}}'
        # 2. Attack in Body (Raw)
        else:
            path = "/hack"
            body = attack
            
        paths.append(path)
        bodies.append(body)

    return pd.DataFrame({'path': paths, 'body': bodies, 'label': 1})

# Combine
df_good = generate_good_data()
df_bad = generate_bad_data()
df = pd.concat([df_good, df_bad]).sample(frac=1, random_state=42).reset_index(drop=True)

X = df[['path', 'body']]
y = df['label']

print(f"Training on {len(df)} samples...")

# --- 3. PIPELINE ---
def get_body(df): return df['body']

pipeline = Pipeline([
    ('features', FeatureUnion([
        ('body_char', Pipeline([
            ('selector', FunctionTransformer(get_body, validate=False)),
            ('tfidf', TfidfVectorizer(analyzer='char', ngram_range=(3, 5), max_features=5000))
        ])),
        ('body_word', Pipeline([
            ('selector', FunctionTransformer(get_body, validate=False)),
            ('tfidf', TfidfVectorizer(analyzer='word', token_pattern=r'(?u)\b\w+\b', max_features=2000))
        ])),
    ])),
    ('classifier', RandomForestClassifier(n_estimators=50, random_state=42))
])

pipeline.fit(X, y)

# --- 4. SELF TEST ---
print("\n--- FINAL SELF TEST ---")
test_cases = [
    {"path": "/login", "body": '{"user": "jim"}'},   # JSON Safe
    {"path": "/contact", "body": ''},                # Empty Safe (This failed before)
    {"path": "/hack", "body": 'UNION SELECT *'}      # Attack
]
for test in test_cases:
    df_test = pd.DataFrame([test])
    score = pipeline.predict_proba(df_test)[0][1]
    print(f"Body: '{test['body']}' -> Score: {score:.4f}")
    
# 5. Save
os.makedirs('model', exist_ok=True)
joblib.dump(pipeline, 'model/waf_model.joblib')
print("\nModel saved.")