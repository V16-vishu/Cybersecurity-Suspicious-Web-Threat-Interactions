import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from joblib import dump
from pathlib import Path

from utils import load_raw_csv, to_datetime, add_session_features, basic_sanity

DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "CloudWatch_Traffic_Web_Attack.csv"
ARTIFACTS = Path(__file__).resolve().parents[1] / "artifacts"
ARTIFACTS.mkdir(parents=True, exist_ok=True)

def main():
    df = load_raw_csv(str(DATA_PATH))
    df = to_datetime(df, ["creation_time","end_time","time"])
    df = add_session_features(df)
    df = basic_sanity(df)

    features = ["bytes_in","bytes_out","session_duration","avg_packet_size"]
    X = df[features].replace([np.inf, -np.inf], np.nan).dropna()

    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    model = IsolationForest(contamination=0.05, random_state=42)
    preds = model.fit_predict(Xs)

    # map to labels
    df = df.loc[X.index].copy()
    df["anomaly"] = np.where(preds == -1, "Suspicious", "Normal")

    # save artifacts
    df.to_parquet(ARTIFACTS / "anomaly_scored.parquet", index=False)
    dump(model, ARTIFACTS / "iforest.joblib")
    dump(scaler, ARTIFACTS / "scaler.joblib")

if __name__ == "__main__":
    main()