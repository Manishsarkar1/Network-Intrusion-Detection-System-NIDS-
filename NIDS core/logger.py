# logger.py
import sqlite3
import threading
from datetime import datetime

DB_PATH = "nids_alerts.db"

class Logger:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts REAL, src TEXT, dst TEXT, proto TEXT, alert TEXT
                    )""")
        conn.commit()
        conn.close()

    def alert(self, ts, src, dst, proto, message):
        # Store to DB and print to stdout
        try:
            with self._lock:
                conn = sqlite3.connect(self.db_path, check_same_thread=False)
                c = conn.cursor()
                c.execute("INSERT INTO alerts (ts, src, dst, proto, alert) VALUES (?,?,?,?,?)",
                          (ts, src, dst, proto, message))
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
