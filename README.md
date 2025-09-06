# Cybersecurity: Suspicious Web Threat Interactions
End‑to‑end project to detect and analyze suspicious web traffic (AWS CloudWatch style).

## Folder layout
```
cybersec_web_threat_project/
├── Cybersecurity_Web_Threat_Project.ipynb   # main notebook (run top→bottom)
├── requirements.txt                          # Python packages
├── outputs/                                  # saved figures & CSVs after running notebook
└── README.md
```

## Quick start
1) **Create a fresh Python env** (recommended):
   - `python -m venv venv && source venv/bin/activate` (Linux/Mac)
   - `py -m venv venv && venv\Scripts\activate` (Windows)

2) **Install requirements**:
   ```bash
   pip install -r requirements.txt
   ```

3) **Put the dataset CSV** (e.g., `CloudWatch_Traffic_Web_Attack.csv`) somewhere on your machine.
   - You can also place it right next to the notebook.

4) **Open the notebook** `Cybersecurity_Web_Threat_Project.ipynb` and set `DATA_PATH` in the first cell
   to the location of your CSV file, then run all cells.

## What you'll get
- Cleaned dataframe with proper dtypes
- EDA plots (bytes_in/out distributions, protocols, countries, time series)
- Feature engineering (session_duration, avg_packet_size, totals/log features)
- **Anomaly detection** using Isolation Forest
- **(Optional) Supervised classification** with RandomForest if a label proxy exists (`detection_types == "waf_rule"`)
- Saved outputs in `outputs/`: 
  - `anomalies.csv`: rows flagged as suspicious by Isolation Forest
  - `rf_feature_importance.png`: RandomForest feature importance bar chart (if classification part is run)
  - `summary_report.md`: short project summary and next steps

## Notes
- Plots use `matplotlib` only.
- The notebook is defensive against missing columns (e.g., if `detection_types` is not present, the classification step is skipped).
- Tweak the Isolation Forest `contamination` hyperparameter if you think the percentage of anomalies is higher/lower.
