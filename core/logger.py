"""
PacketReaper - Session Logger
Writes structured JSON-L logs per session + CSV export support.
"""

import json
import csv
import os
import time
from dataclasses import asdict
from pathlib import Path


class SessionLogger:
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self._session_file = None
        self._session_path = None
        self._record_count = 0

    def start_session(self) -> str:
        ts = time.strftime("%Y-%m-%d_%H-%M-%S")
        self._session_path = self.log_dir / f"session_{ts}.jsonl"
        self._session_file = open(self._session_path, "a")
        self._record_count = 0
        return str(self._session_path)

    def log(self, record):
        if not self._session_file:
            return
        entry = asdict(record) if hasattr(record, "__dataclass_fields__") else record
        self._session_file.write(json.dumps(entry) + "\n")
        self._session_file.flush()
        self._record_count += 1

    def end_session(self) -> dict:
        if self._session_file:
            self._session_file.close()
            self._session_file = None
        return {
            "path": str(self._session_path),
            "records": self._record_count,
        }

    def list_sessions(self):
        return sorted(self.log_dir.glob("session_*.jsonl"), reverse=True)

    def export_csv(self, jsonl_path: str) -> str:
        src = Path(jsonl_path)
        dst = src.with_suffix(".csv")
        with open(src) as f_in, open(dst, "w", newline="") as f_out:
            writer = None
            for line in f_in:
                row = json.loads(line)
                if writer is None:
                    writer = csv.DictWriter(f_out, fieldnames=row.keys())
                    writer.writeheader()
                writer.writerow(row)
        return str(dst)
