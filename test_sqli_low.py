import sqlite3

import pytest

import vulnerabilities.SQLi as SQLi


class FakeDBManager:
    """Base SQLite en mémoire : le test ne touche pas TIWAP.db."""

    def __init__(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute(
            "CREATE TABLE users (userid INTEGER, username TEXT, password TEXT)"
        )
        self.conn.execute("INSERT INTO users VALUES (1, 'alice', 'secret-alice')")
        self.conn.execute("INSERT INTO users VALUES (2, 'bob', 'secret-bob')")

    def get_db_connection(self):
        return self.conn

    def check_user(self, username):
        return False


@pytest.fixture(autouse=True)
def fake_db(monkeypatch):
    monkeypatch.setattr(SQLi, "dbmanager", FakeDBManager())


def test_identifiants_valides_fonctionnent():
    assert SQLi.sqli_low("alice", "secret-alice") == [(1, "alice")]


def test_mauvais_mot_de_passe_ne_renvoie_rien():
    assert SQLi.sqli_low("alice", "faux") == []


def test_injection_dans_le_mot_de_passe_neutralisee():
    assert SQLi.sqli_low("alice", "' OR '1'='1") == []


def test_injection_dans_le_nom_utilisateur_neutralisee():
    assert SQLi.sqli_low("' OR '1'='1' --", "x") == []
