# logger.py
import csv
import sqlite3
import threading
from datetime import datetime
from pathlib import Path

try:
    from nids_core.config import DB_PATH
except ImportError:
    DB_PATH = str(Path(__file__).resolve().parents[1] / "data" / "nids_alerts.db")


class Logger:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        c = conn.cursor()
        c.execute(
            """CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts REAL, src TEXT, dst TEXT, proto TEXT, alert TEXT
                    )"""
        )
        conn.commit()
        conn.close()

    def alert(self, ts, src, dst, proto, message):
        # Store to DB and print to stdout
        try:
            with self._lock:
                conn = sqlite3.connect(self.db_path, check_same_thread=False)
                c = conn.cursor()
                c.execute(
                    "INSERT INTO alerts (ts, src, dst, proto, alert) VALUES (?,?,?,?,?)",
                    (ts, src, dst, proto, message),
                )
                conn.commit()
                conn.close()
        except Exception as e:
            print("[LOGGER] DB insert failed:", e)

        # Also print for quick feedback
        tstr = datetime.fromtimestamp(ts)
        print(f"[ALERT] {tstr} | {src} -> {dst} | {proto} | {message}")

    def recent(self, limit=50):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        c = conn.cursor()
        c.execute("SELECT ts, src, dst, proto, alert FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
        rows = c.fetchall()
        conn.close()
        return rows

    def export_csv(self, output_path, limit=500):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        c = conn.cursor()
        c.execute(
            "SELECT ts, src, dst, proto, alert FROM alerts ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        rows = c.fetchall()
        conn.close()

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        with out.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "source", "destination", "protocol", "alert"])
            for ts, src, dst, proto, alert in rows:
                writer.writerow(
                    [
                        datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),
                        src,
                        dst,
                        proto,
                        alert,
                    ]
                )

        return len(rows)
