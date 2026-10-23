"""
backup_restore.py  Business Continuity & Disaster Recovery Utility.

Design Decisions (IT Audit / BCP-DR Perspective):
- Aligns with ISO 27001:2022 A.8.13 (Information Backup) and ISO 22301 (Business Continuity).
- Uses SQLite's online backup API (conn.backup) to guarantee atomic snapshots
  even while transactions or reads are taking place (no corrupted intermediate state).
- Generates SHA-256 integrity checksums for every backup artifact to detect
  bit-rot or offline data tampering.
- Performs 'PRAGMA integrity_check' before taking a backup and after restoring.
"""

import os
import sys
import sqlite3
import hashlib
import shutil
import subprocess
import tempfile
from datetime import datetime

import db
import config

BACKUP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backups")


def _mysql_cli_env() -> dict:
    """Pass the password through MYSQL_PWD instead of exposing it in argv."""
    env = os.environ.copy()
    env["MYSQL_PWD"] = config.DB_PASSWORD
    return env


def _write_checksum(backup_path: str) -> str:
    checksum = compute_file_sha256(backup_path)
    with open(f"{backup_path}.sha256", "w", encoding="utf-8") as f:
        f.write(checksum)
    return checksum


def _perform_mysql_backup() -> str:
    """Create a consistent logical MySQL backup using mysqldump."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    backup_path = os.path.join(BACKUP_DIR, f"banking_backup_{timestamp}.sql")
    command = [
        "mysqldump",
        "--single-transaction",
        "--routines",
        "--triggers",
        "--host",
        config.DB_HOST,
        "--port",
        str(config.DB_PORT),
        "--user",
        config.DB_USER,
        "--result-file",
        backup_path,
        config.DB_NAME,
    ]
    try:
        subprocess.run(
            command, env=_mysql_cli_env(), check=True, capture_output=True, text=True
        )
    except FileNotFoundError as exc:
        raise RuntimeError("mysqldump is required for MySQL backups") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"mysqldump failed: {exc.stderr.strip()}") from exc
    checksum = _write_checksum(backup_path)
    print("[+] MySQL backup completed successfully:")
    print(f"    File:     {backup_path}")
    print(f"    SHA-256:  {checksum}")
    return backup_path


def compute_file_sha256(filepath: str) -> str:
    """Compute SHA-256 hash of a file for integrity verification."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def perform_backup() -> str:
    """
    Perform an online, consistent backup of the database.
    Returns the path to the created backup file.
    """
    os.makedirs(BACKUP_DIR, exist_ok=True)
    if db.DB_TYPE == "mysql":
        return _perform_mysql_backup()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    backup_filename = f"banking_backup_{timestamp}.db"
    backup_path = os.path.join(BACKUP_DIR, backup_filename)

    # Step 1: Verify source database integrity prior to backup
    src_conn = db.get_connection()
    try:
        if db.is_mysql_connection(src_conn):
            raise RuntimeError("DB_TYPE and connection engine disagree")
        check = src_conn.execute("PRAGMA integrity_check").fetchone()[0]
        if check != "ok":
            raise RuntimeError(f"Source database integrity check failed: {check}")

        # Step 2: Use SQLite online backup API for safe hot-backup
        dest_conn = sqlite3.connect(backup_path)
        try:
            src_conn.backup(dest_conn)
        finally:
            dest_conn.close()
    finally:
        src_conn.close()

    # Step 3: Compute and write SHA-256 checksum
    checksum = _write_checksum(backup_path)

    print("[+] Backup completed successfully:")
    print(f"    File:     {backup_path}")
    print(f"    SHA-256:  {checksum}")
    return backup_path


def restore_backup(backup_path: str) -> bool:
    """
    Restore the database from a verified backup file.
    Validates checksum and schema integrity before replacing live DB.
    """
    if not os.path.exists(backup_path):
        print(f"[!] Backup file not found: {backup_path}")
        return False

    checksum_path = f"{backup_path}.sha256"
    if not os.path.exists(checksum_path):
        print(
            "[!] Checksum sidecar is missing; refusing to restore an unverified backup."
        )
        return False
    with open(checksum_path, "r", encoding="utf-8") as f:
        expected_checksum = f.read().strip()
    actual_checksum = compute_file_sha256(backup_path)
    if expected_checksum != actual_checksum:
        print("[!] CRITICAL: Checksum verification failed! File may be corrupted.")
        print(f"    Expected: {expected_checksum}")
        print(f"    Actual:   {actual_checksum}")
        return False
    print(f"[+] Checksum verification passed ({actual_checksum[:16]}...)")

    if db.DB_TYPE == "mysql":
        try:
            with open(backup_path, "rb") as dump_file:
                subprocess.run(
                    [
                        "mysql",
                        "--host",
                        config.DB_HOST,
                        "--port",
                        str(config.DB_PORT),
                        "--user",
                        config.DB_USER,
                        config.DB_NAME,
                    ],
                    env=_mysql_cli_env(),
                    stdin=dump_file,
                    check=True,
                    capture_output=True,
                    text=False,
                )
        except FileNotFoundError:
            print("[!] mysql client is required for MySQL restore.")
            return False
        except subprocess.CalledProcessError as exc:
            print(
                f"[!] MySQL restore failed: {exc.stderr.decode(errors='replace').strip()}"
            )
            return False
        print(f"[+] MySQL database restored successfully from: {backup_path}")
        return True

    # Verify backup database integrity
    chk_conn = sqlite3.connect(backup_path)
    try:
        check = chk_conn.execute("PRAGMA integrity_check").fetchone()[0]
        if check != "ok":
            print(f"[!] Backup file failed PRAGMA integrity_check: {check}")
            return False
    finally:
        chk_conn.close()

    # Create safety snapshot of live database before overwriting
    if os.path.exists(db.DB_PATH):
        pre_restore_backup = (
            f"{db.DB_PATH}.pre_restore_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
        )
        shutil.copy2(db.DB_PATH, pre_restore_backup)
        print(f"[*] Pre-restore safety snapshot saved to: {pre_restore_backup}")

    # Replace atomically within the target directory. A partial copy must not
    # become the live database if the process is interrupted.
    target_dir = os.path.dirname(os.path.abspath(db.DB_PATH)) or "."
    os.makedirs(target_dir, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(
        prefix=".banking_restore_", suffix=".db", dir=target_dir
    )
    os.close(fd)
    try:
        shutil.copy2(backup_path, temp_path)
        os.replace(temp_path, db.DB_PATH)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    print(f"[+] Database restored successfully from: {backup_path}")
    return True


def list_backups() -> list:
    """List all available backups in BACKUP_DIR."""
    if not os.path.exists(BACKUP_DIR):
        print("No backups directory found.")
        return []

    backups = [f for f in os.listdir(BACKUP_DIR) if f.endswith((".db", ".sql"))]
    backups.sort(reverse=True)
    if not backups:
        print("No backup files found.")
        return []

    print("\n--- Available Backups ---")
    for b in backups:
        b_path = os.path.join(BACKUP_DIR, b)
        size_kb = os.path.getsize(b_path) / 1024
        print(f"  {b} ({size_kb:.1f} KB)")
    return backups


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python backup_restore.py [backup|restore <file>|list]")
        sys.exit(1)

    cmd = sys.argv[1].lower()
    if cmd == "backup":
        perform_backup()
    elif cmd == "restore":
        if len(sys.argv) < 3:
            print("Usage: python backup_restore.py restore <backup_path>")
            sys.exit(1)
        restore_backup(sys.argv[2])
    elif cmd == "list":
        list_backups()
    else:
        print(f"Unknown command: {cmd}")
