"""
app.py
Application entrypoint for the PowerPlay Sports Systems
Issue & Vulnerability Tracking System.

Author: self
"""
import os
from flask import Flask, send_from_directory

import db as dblayer
from routes import api

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "..", "frontend")


def create_app(db_path=None):
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path or dblayer.DB_PATH

    if db_path:
        dblayer.DB_PATH = db_path

    dblayer.init_db(app.config["DB_PATH"])
    app.register_blueprint(api)

    # allow the frontend (running from any origin) to call this API
    @app.after_request
    def add_cors_headers(resp):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        resp.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,PATCH,DELETE,OPTIONS"
        return resp

    # serve the frontend from the same server, for convenience
    @app.route("/")
    def index():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.route("/<path:filename>")
    def static_files(filename):
        return send_from_directory(FRONTEND_DIR, filename)

    return app