import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import StandardScaler
from joblib import dump
from pathlib import Path

from utils import load_raw_csv, to_datetime, add_session_features, make_label, basic_sanity

DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "CloudWatch_Traffic_Web_Attack.csv"
ARTIFACTS = Path(__file__).resolve().parents[1] / "artifacts"
ARTIFACTS.mkdir(parents=True, exist_ok=True)

def main():
    df = load_raw_csv(str(DATA_PATH))
    df = to_datetime(df, ["creation_time","end_time","time"])
    df = add_session_features(df)
    df = basic_sanity(df)
    y = make_label(df.get("detection_types", pd.Series(index=df.index)))
    features = ["bytes_in","bytes_out","session_duration","avg_packet_size"]
    X = df[features].replace([np.inf, -np.inf], np.nan).fillna(0)

    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(Xs, y, test_size=0.3, random_state=42, stratify=y)

    rf = RandomForestClassifier(n_estimators=300, random_state=42, class_weight="balanced")
    rf.fit(X_train, y_train)
    y_pred = rf.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print(classification_report(y_test, y_pred))

    dump(rf, ARTIFACTS / "rf_model.joblib")
    dump(scaler, ARTIFACTS / "rf_scaler.joblib")

if __name__ == "__main__":
    main()