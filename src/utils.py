import pandas as pd
import numpy as np

EXPECTED_COLUMNS = [
    "bytes_in","bytes_out","creation_time","end_time","src_ip","src_ip_country_code",
    "protocol","response.code","dst_port","dst_ip","rule_names","observation_name",
    "source.meta","source.name","time","detection_types"
]

def load_raw_csv(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    # keep only expected columns if present
    cols = [c for c in EXPECTED_COLUMNS if c in df.columns]
    df = df[cols].copy()
    return df

def to_datetime(df: pd.DataFrame, cols):
    for c in cols:
        if c in df.columns:
            df[c] = pd.to_datetime(df[c], errors="coerce")
    return df

def add_session_features(df: pd.DataFrame) -> pd.DataFrame:
    # duration
    if {"creation_time","end_time"}.issubset(df.columns):
        df["session_duration"] = (df["end_time"] - df["creation_time"]).dt.total_seconds()
    else:
        df["session_duration"] = np.nan
    # protect against zero or negative durations
    safe_duration = df["session_duration"].where(df["session_duration"]>0, np.nan)
    # average packet size proxy
    df["avg_packet_size"] = (df.get("bytes_in",0) + df.get("bytes_out",0)) / safe_duration
    return df

def make_label(detection_series: pd.Series) -> pd.Series:
    s = detection_series.astype(str).str.lower()
    # treat 'normal' explicitly as 0; anything that looks like attack/waf/suspicious -> 1
    suspicious = s.str.contains("waf|attack|suspici|anomal", regex=True)
    label = suspicious.astype(int)
    return label

def basic_sanity(df: pd.DataFrame) -> pd.DataFrame:
    # drop full-NA rows
    df = df.dropna(how="all").copy()
    # enforce non-negative numeric
    for col in ["bytes_in","bytes_out","session_duration","avg_packet_size"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    return df