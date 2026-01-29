"""
simulate_traffic.py

Purpose:
- Simulate real-time network traffic using processed feature data
- Continuously evaluate traffic windows using the Hybrid IDS
- Print and store alerts when intrusions are detected

This replaces live network traffic for demo/testing.
"""

import time
import sqlite3
import pandas as pd
from pathlib import Path
from datetime import datetime

from decision_engine import get_decision_engine


# ==============================
# Paths & Config
# ==============================
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = BASE_DIR / "models" / "processed_features.csv"
DB_PATH = BASE_DIR / "db" / "alerts.db"

SLEEP_SECONDS = 1          # simulate 1 window per second
ALERT_THRESHOLD = 0.7      # must match decision_engine


# ==============================
# Database Setup
# ==============================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ml_score REAL,
            rule_score REAL,
            final_score REAL,
            severity TEXT,
            matched_rules TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_alert(result: dict):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts (
            timestamp,
            ml_score,
            rule_score,
            final_score,
            severity,
            matched_rules
        ) VALUES (?, ?, ?, ?, ?, ?)
    """, (
        datetime.utcnow().isoformat(),
        result["ml_score"],
        result["rule_score"],
        result["final_score"],
        result["severity"],
        ",".join([r["rule_id"] for r in result["matched_rules"]])
    ))

    conn.commit()
    conn.close()


# ==============================
# Traffic Simulation
# ==============================
def simulate():
    print("\n🚦 Starting real-time traffic simulation...\n")

    df = pd.read_csv(DATA_PATH)
    engine = get_decision_engine()

    print(f"Loaded {len(df)} traffic windows")
    print(f"Streaming one window every {SLEEP_SECONDS} second(s)\n")

    for idx, row in df.iterrows():
        features = row.to_dict()

        result = engine.evaluate(features)

        if result["is_intrusion"]:
            print("🚨 INTRUSION DETECTED")
            print(f"   ML score     : {result['ml_score']}")
            print(f"   Rule score   : {result['rule_score']}")
            print(f"   Final score  : {result['final_score']}")
            print(f"   Severity     : {result['severity']}")
            print(f"   Rules hit    : {[r['rule_id'] for r in result['matched_rules']]}")
            print("-" * 50)

            save_alert(result)
        else:
            print(f"✔ Normal traffic | score={result['final_score']}")

        time.sleep(SLEEP_SECONDS)


# ==============================
# Main
# ==============================
if __name__ == "__main__":
    init_db()
    simulate()
