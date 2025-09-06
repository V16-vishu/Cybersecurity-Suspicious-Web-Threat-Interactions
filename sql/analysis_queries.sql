-- Create table (run is optional if using pandas.to_sql to create)
-- CREATE TABLE IF NOT EXISTS web_traffic (
--   bytes_in INTEGER, bytes_out INTEGER,
--   creation_time TEXT, end_time TEXT, time TEXT,
--   src_ip TEXT, src_ip_country_code TEXT, protocol TEXT,
--   response_code INTEGER, dst_port INTEGER, dst_ip TEXT,
--   rule_names TEXT, observation_name TEXT, source_meta TEXT, source_name TEXT,
--   detection_types TEXT
-- );

-- 1) Top talkers by bytes_in
SELECT src_ip, SUM(bytes_in) AS total_in
FROM web_traffic
GROUP BY src_ip
ORDER BY total_in DESC
LIMIT 10;

-- 2) Volume by country
SELECT src_ip_country_code, COUNT(*) AS hits,
       SUM(bytes_in + bytes_out) AS total_bytes
FROM web_traffic
GROUP BY src_ip_country_code
ORDER BY hits DESC;

-- 3) Suspicious share by country
SELECT src_ip_country_code,
       AVG(CASE WHEN detection_types LIKE '%waf%' OR detection_types LIKE '%suspici%' THEN 1 ELSE 0 END) AS suspicious_rate
FROM web_traffic
GROUP BY src_ip_country_code
ORDER BY suspicious_rate DESC;

-- 4) Time-of-day histogram (hourly)
SELECT STRFTIME('%H', creation_time) AS hour, COUNT(*) AS events
FROM web_traffic
GROUP BY hour
ORDER BY hour;