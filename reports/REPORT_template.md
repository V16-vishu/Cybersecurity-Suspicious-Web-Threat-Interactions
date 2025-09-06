# Suspicious Web Threat Interactions — Findings

## Objective
Detect and analyze patterns in web interactions to identify suspicious or potentially harmful activities.

## Dataset
- Source: AWS CloudWatch-derived web traffic logs (labeled for suspicious behavior)
- Key fields: bytes_in, bytes_out, src_ip, dst_ip, protocol, response.code, dst_port, src_ip_country_code, timestamps, rule_names, detection_types

## Methods
- Cleaning & typing of timestamps
- Feature engineering: session_duration, avg_packet_size
- Anomaly detection: IsolationForest (unsupervised)
- Supervised baseline: RandomForest (if labels available)
- SQL analytics: top talkers, country distribution, suspicious share

## Highlights
- [Add your key charts and bullet insights here]
- Example: "High bytes_in but low bytes_out sessions concentrated on dst_port 443; potential infiltration attempts."
- Example: "Spike from specific country codes during 23:00–23:10 UTC; possibly coordinated probes."

## Risk Interpretation & Next Steps
- Review IPs with repeated anomalies
- Add threat intel enrichment (ASN, reputation lists)
- Deploy model thresholds with alerting
- Validate against benign traffic to reduce false positives