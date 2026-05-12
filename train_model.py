import os
import pickle

import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# ── Paths ──────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DATASET     = os.path.join(BASE_DIR, "dataset.csv")
MODELS_DIR  = os.path.join(BASE_DIR, "models")
FEATURES    = ["url_length", "has_https", "special_char_count", "has_ip"]

# ── Load dataset ───────────────────────────────────────────────────────────
print("Loading dataset...")
df = pd.read_csv(DATASET)
print(f"  Total   : {len(df)} samples")
print(f"  Safe    : {len(df[df['label'] == 0])}")
print(f"  Malicious: {len(df[df['label'] == 1])}")

X = df[FEATURES].values
y = df["label"].values

# ── Scale features ─────────────────────────────────────────────────────────
scaler   = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ── Train / test split ─────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)

# ── Train model ────────────────────────────────────────────────────────────
print("\nTraining Logistic Regression model...")
model  = LogisticRegression(C=1.0, max_iter=500, random_state=42)
model.fit(X_train, y_train)

# ── Evaluate ───────────────────────────────────────────────────────────────
y_pred   = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy * 100:.2f}%\n")
print(classification_report(y_test, y_pred, target_names=["Safe", "Malicious"]))

cm = confusion_matrix(y_test, y_pred)
print(f"Confusion Matrix:  TN={cm[0][0]}  FP={cm[0][1]}  FN={cm[1][0]}  TP={cm[1][1]}")

# ── Save model artifacts ───────────────────────────────────────────────────
os.makedirs(MODELS_DIR, exist_ok=True)

with open(os.path.join(MODELS_DIR, "model.pkl"), "wb") as f:
    pickle.dump(model, f)

with open(os.path.join(MODELS_DIR, "scaler.pkl"), "wb") as f:
    pickle.dump(scaler, f)

print("\nSaved: model.pkl, scaler.pkl")
print("Done. Run app.py to start the server.")