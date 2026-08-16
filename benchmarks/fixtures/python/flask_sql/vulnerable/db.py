"""Deliberately vulnerable cross-file SQL sink. Do not deploy."""

import sqlite3


def lookup_user(name: str):
    database = sqlite3.connect("users.db")
    return database.execute("SELECT * FROM users WHERE name = '" + name + "'").fetchall()
