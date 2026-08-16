"""Patched benchmark equivalent. It is still not a deployable application."""

from flask import Flask, request

from db import lookup_user

app = Flask(__name__)


@app.get("/users")
def users():
    return lookup_user(request.args["name"])
