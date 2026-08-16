"""Deliberately vulnerable benchmark fixture. Do not deploy."""

from flask import Flask, request

from db import lookup_user

app = Flask(__name__)


@app.get("/users")
def users():
    return lookup_user(request.args["name"])
