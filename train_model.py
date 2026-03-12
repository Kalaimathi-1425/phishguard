# train_model.py
import pandas as pd
import joblib
import warnings
warnings.filterwarnings("ignore")

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from xgboost import XGBClassifier
from feature_extractor import extract_features

def build_dataset(phish_limit=5000, legit_limit=5000):
    print("[*] Loading datasets...")

    phish = pd.read_csv("phishtank.csv")[["url"]].dropna()
    phish = phish.sample(
        min(phish_limit, len(phish)), random_state=42)
    phish["label"] = 1

    legit = pd.read_csv("top-1m.csv",
        header=None, names=["rank", "domain"])
    legit["url"] = "https://" + legit["domain"]
    legit = legit.sample(legit_limit, random_state=42)
    legit["label"] = 0

    df = pd.concat([phish[["url","label"]],
                    legit[["url","label"]]])
    return df.sample(frac=1, random_state=42).reset_index(drop=True)

def extract_all(df):
    print(f"[*] Extracting features from {len(df)} URLs...")
    rows = []
    for i, row in df.iterrows():
        try:
            feat = extract_features(row["url"])
            feat["label"] = row["label"]
            rows.append(feat)
        except Exception:
            pass

        if (i + 1) % 100 == 0:
            pct = ((i + 1) / len(df)) * 100
            print(f"  → {i+1}/{len(df)} done ({pct:.0f}%)")

    return pd.DataFrame(rows).fillna(-1)

def train(feat_df):
    X = feat_df.drop("label", axis=1)
    y = feat_df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y)

    print("\n[*] Training XGBoost model...")
    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42
    )
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    print("\n===== Model Performance =====")
    print(classification_report(
        y_test, preds, target_names=["Legit","Phishing"]))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, preds))

    joblib.dump(model, "phishing_model.pkl")
    joblib.dump(list(X.columns), "feature_columns.pkl")
    print("\n[+] Model saved → phishing_model.pkl")

if __name__ == "__main__":
    df       = build_dataset()
    feat_df  = extract_all(df)
    train(feat_df)
