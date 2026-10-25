ML-Driven Network Intrusion Detection System (NIDS) |Built for SIH 2026|

An intelligent, real-time Network Intrusion Detection System (NIDS) engineered to identify, classify, and alert on multi-vector cyber threats in high-throughput network environments.

By combining Scapy-based packet ingestion, RandomForest machine learning, JA3/JA4 cryptographic fingerprinting, and live DGAArchive Threat Intelligence, this system provides full-spectrum visibility into stealthy attack vectors while maintaining zero false positives on benign enterprise traffic.

📸 Dashboard Overview

The platform includes a high-performance Node.js Command Center Dashboard that streams real-time telemetry, live bandwidth statistics (Mbps / FPS), and high-confidence security alerts (Confidence >= 80%).

🎯 Target Threat Vectors Covered

This NIDS is specifically tuned to detect 6 primary threat vectors:

Reconnaissance & Port Scanning: High-frequency TCP SYN fan-outs across multiple destination ports.

Volumetric & Protocol DDoS: High-rate TCP SYN floods targeted at single or narrow port ranges.

Botnet C2 Beaconing: Automated ICMP/TCP heartbeats identified via time-interval variance analysis.

DGA & DNS Tunnelling:

DGA: Real-time lookup via DGAArchive API (with recursive JSON inspection) + Entropy Heuristics.

DNS Tunnelling: Oversized DNS query payloads and high-volume TXT record requests.

Encrypted Session Malware: Raw TLS payload inspection using JA3 and JA4 (QUIC) client hello hashing.

Data Exfiltration: Large, unidirectional outbound data transfers crossing internal-to-external network boundaries.

✨ Key Features & Technical Highlights

Deep Inspection DGA API Engine: Integrates directly with the Fraunhofer FKIE DGAArchive API. Features a recursive JSON parser (has_family()) to ensure benign domains returning status 200 (e.g., google.com, `ubuntu.
