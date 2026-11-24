"""Almacenamiento del servidor en SQLite.

Antes todo iba en un JSON que se reescribía entero en cada cambio: con muchos usuarios es
lento y, si se cortaba la luz justo al guardar, se podía perder. Ahora cada cuenta es una fila
y cada cola de mensajes, otra tabla; solo se escribe lo que cambia y siempre dentro de una
transacción (SQLite en modo WAL), así que un corte a medias no deja nada roto.

El servidor sigue teniendo los datos en memoria; esto solo los guarda y los carga al arrancar.
Al encontrar los ficheros del formato antiguo (usuarios.json y la carpeta de la cola), los pasa
a la base de datos una vez y los deja renombrados como copia (*.migrado).
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path


class Store:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        # El servidor de la bandeja la abre en un hilo y atiende las conexiones en otro:
        # se permite usarla desde cualquier hilo, pero nunca desde dos a la vez (candado).
        self.db = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)  # transacciones a mano
        self._lock = threading.RLock()
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS accounts (canon TEXT PRIMARY KEY, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS queue (id INTEGER PRIMARY KEY AUTOINCREMENT, qk TEXT NOT NULL, item TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS queue_qk ON queue (qk);
            CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
        """)
        self._written: dict[str, str] = {}

    # ------------------------------------------------------------ cuentas

    def load_accounts(self) -> dict[str, dict]:
        out = {}
        for canon, data in self.db.execute("SELECT canon, data FROM accounts"):
            self._written[canon] = data
            out[canon] = json.loads(data)
        return out

    def save_accounts(self, accounts: dict[str, dict]) -> None:
        """Guarda las cuentas que han cambiado desde la última vez y borra las que ya no están."""
        rows = {c: json.dumps(v, sort_keys=True, separators=(",", ":")) for c, v in accounts.items()}
        changed = [(c, d) for c, d in rows.items() if self._written.get(c) != d]
        gone = [c for c in self._written if c not in rows]
        if not changed and not gone:
            return
        with self._tx():
            self.db.executemany("INSERT INTO accounts (canon, data) VALUES (?, ?) "
                                "ON CONFLICT(canon) DO UPDATE SET data = excluded.data", changed)
            self.db.executemany("DELETE FROM accounts WHERE canon = ?", [(c,) for c in gone])
        self._written.update(changed)
        for c in gone:
            self._written.pop(c, None)

    def empty(self) -> bool:
        return self.db.execute("SELECT NOT EXISTS (SELECT 1 FROM accounts)").fetchone()[0] == 1

    # ------------------------------------------------------------ colas

    def load_queues(self) -> dict[str, list[dict]]:
        out: dict[str, list[dict]] = {}
        for qk, item in self.db.execute("SELECT qk, item FROM queue ORDER BY id"):
            out.setdefault(qk, []).append(json.loads(item))
        return out

    def save_queue(self, qk: str, items: list[dict]) -> None:
        with self._tx():
            self.db.execute("DELETE FROM queue WHERE qk = ?", (qk,))
            self.db.executemany("INSERT INTO queue (qk, item) VALUES (?, ?)", [(qk, json.dumps(x)) for x in items])

    def queued_count(self, prefix: str = "") -> int:
        return self.db.execute("SELECT COUNT(*) FROM queue WHERE qk LIKE ?", (prefix + "%",)).fetchone()[0]

    # ------------------------------------------------------------ varios

    def _tx(self):
        db = self.db

        lock = self._lock

        class Tx:
            def __enter__(self):
                lock.acquire()
                try:
                    db.execute("BEGIN IMMEDIATE")
                except BaseException:
                    lock.release()
                    raise

            def __exit__(self, exc, *_):
                try:
                    db.execute("ROLLBACK" if exc else "COMMIT")
                finally:
                    lock.release()
                return False
        return Tx()

    def backup(self, dest: Path) -> None:
        """Copia consistente aunque el servidor esté escribiendo (para las copias de seguridad)."""
        target = sqlite3.connect(str(dest))
        with target:
            self.db.backup(target)
        target.close()

    def close(self) -> None:
        self.db.close()


def migrate_legacy(store: Store, json_path: Path | None, queue_dir: Path | None) -> None:
    """Pasa usuarios.json y la carpeta de la cola (formato antiguo) a SQLite, una sola vez."""
    if json_path and json_path.exists() and store.empty():
        data = json.loads(json_path.read_text(encoding="utf-8"))
        accounts = {}
        for name, v in data.items():
            if isinstance(v, str):  # formato muy antiguo: {"nombre": "clave"}
                v = {"name": name, "key": v}
            accounts[v["name"].lower()] = v
        store.save_accounts(accounts)
        json_path.rename(json_path.with_name(json_path.name + ".migrado"))
    if queue_dir and queue_dir.is_dir():
        files = list(queue_dir.glob("*__*.json"))
        for f in files:
            c, dev = f.stem.split("__", 1)
            store.save_queue(f"{c}|{dev}", json.loads(f.read_text(encoding="utf-8")))
        if files:
            queue_dir.rename(queue_dir.with_name(queue_dir.name + ".migrado"))
