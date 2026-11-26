import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from parsers import parse_log_line

DB_NAME = "minisoc.db"


def get_connection(db_path: str = DB_NAME) -> sqlite3.Connection:
    """Retourne une connexion SQLite avec gestion des clés étrangères."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: str = DB_NAME) -> None:
    """Initialise les tables imports, events et alerts si elles n'existent pas."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS imports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                imported_at TEXT NOT NULL,
                lines_read INTEGER NOT NULL DEFAULT 0,
                lines_parsed INTEGER NOT NULL DEFAULT 0,
                lines_ignored INTEGER NOT NULL DEFAULT 0
            );
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                import_id INTEGER NOT NULL,
                timestamp_utc TEXT NOT NULL,
                source_type TEXT NOT NULL,
                src_ip TEXT,
                user_or_method TEXT,
                action_or_resource TEXT,
                status_code INTEGER,
                raw_log TEXT NOT NULL,
                FOREIGN KEY (import_id) REFERENCES imports(id) ON DELETE CASCADE
            );
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                created_at TEXT NOT NULL,
                src_ip TEXT,
                evidence_count INTEGER NOT NULL DEFAULT 1,
                first_seen_utc TEXT,
                last_seen_utc TEXT,
                summary TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open'
            );
            """
        )

        conn.commit()


def ingest_log_file(
    file_path: str,
    source_type: str,
    db_path: str = DB_NAME,
    default_year: int = 2026,
) -> Dict[str, Any]:
    """
    Lit un fichier de logs ('ssh' ou 'http'), normalise les lignes valides,
    enregistre l'import dans 'imports' et insère les événements dans 'events'.
    """
    init_db(db_path)
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Fichier introuvable : {file_path}")

    imported_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines_read = 0
    lines_parsed = 0
    lines_ignored = 0
    parsed_events = []

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            if not raw_line.strip():
                continue
            lines_read += 1
            event = parse_log_line(raw_line, source_type=source_type, default_year=default_year)
            if event is None:
                lines_ignored += 1
            else:
                lines_parsed += 1
                parsed_events.append(event)

    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO imports (filename, imported_at, lines_read, lines_parsed, lines_ignored)
            VALUES (?, ?, ?, ?, ?)
            """,
            (path.name, imported_at, lines_read, lines_parsed, lines_ignored),
        )
        import_id = cursor.lastrowid

        if parsed_events:
            cursor.executemany(
                """
                INSERT INTO events (
                    import_id, timestamp_utc, source_type, src_ip,
                    user_or_method, action_or_resource, status_code, raw_log
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        import_id,
                        ev["timestamp_utc"],
                        ev["source_type"],
                        ev["src_ip"],
                        ev["user_or_method"],
                        ev["action_or_resource"],
                        ev["status_code"],
                        ev["raw_log"],
                    )
                    for ev in parsed_events
                ],
            )
        conn.commit()

    return {
        "import_id": import_id,
        "filename": path.name,
        "lines_read": lines_read,
        "lines_parsed": lines_parsed,
        "lines_ignored": lines_ignored,
    }


if __name__ == "__main__":
    init_db()
    print(f"Base initialisée : {DB_NAME}")