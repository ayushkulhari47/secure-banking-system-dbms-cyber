"""Tests for the SQLite backup/restore utility and its fail-closed behavior."""

import hashlib
import subprocess

import backup_restore
import db


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def test_backup_and_restore_round_trip(tmp_path, monkeypatch):
    db_path = tmp_path / "banking.db"
    monkeypatch.setattr(db, "DB_PATH", str(db_path))
    monkeypatch.setattr(db, "DB_TYPE", "sqlite")
    monkeypatch.setattr(backup_restore, "BACKUP_DIR", str(tmp_path / "backups"))
    db.init_db()

    original = db.get_account_by_id(1)["balance"]
    backup_path = backup_restore.perform_backup()

    conn = db.get_connection()
    conn.execute("UPDATE Accounts SET balance = 1 WHERE account_id = 1")
    conn.close()

    assert backup_restore.restore_backup(backup_path) is True
    assert db.get_account_by_id(1)["balance"] == original


def test_restore_requires_checksum_sidecar(tmp_path, monkeypatch):
    db_path = tmp_path / "banking.db"
    backup_path = tmp_path / "backup.db"
    monkeypatch.setattr(db, "DB_PATH", str(db_path))
    monkeypatch.setattr(db, "DB_TYPE", "sqlite")
    db.init_db()
    backup_path.write_bytes(db_path.read_bytes())

    assert backup_restore.restore_backup(str(backup_path)) is False


def test_restore_rejects_tampered_backup(tmp_path, monkeypatch):
    db_path = tmp_path / "banking.db"
    backup_path = tmp_path / "backup.db"
    monkeypatch.setattr(db, "DB_PATH", str(db_path))
    monkeypatch.setattr(db, "DB_TYPE", "sqlite")
    db.init_db()
    backup_path.write_bytes(db_path.read_bytes())
    (tmp_path / "backup.db.sha256").write_text(_sha256(backup_path), encoding="utf-8")
    with open(backup_path, "ab") as f:
        f.write(b"tampered")

    assert backup_restore.restore_backup(str(backup_path)) is False


def test_mysql_backup_uses_mysqldump(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_TYPE", "mysql")
    monkeypatch.setattr(backup_restore, "BACKUP_DIR", str(tmp_path / "backups"))

    def fake_run(command, **kwargs):
        result_file = command[command.index("--result-file") + 1]
        with open(result_file, "wb") as f:
            f.write(b"logical mysql dump")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(backup_restore.subprocess, "run", fake_run)
    backup_path = backup_restore.perform_backup()
    assert backup_path.endswith(".sql")
    assert (
        tmp_path / "backups" / (backup_path.rsplit("/", 1)[-1] + ".sha256")
    ).exists()


def test_mysql_restore_uses_mysql_client(tmp_path, monkeypatch):
    backup_path = tmp_path / "backup.sql"
    backup_path.write_bytes(b"logical mysql dump")
    (tmp_path / "backup.sql.sha256").write_text(_sha256(backup_path), encoding="utf-8")
    monkeypatch.setattr(db, "DB_TYPE", "mysql")
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(backup_restore.subprocess, "run", fake_run)
    assert backup_restore.restore_backup(str(backup_path)) is True
    assert calls[0][0][0] == "mysql"
