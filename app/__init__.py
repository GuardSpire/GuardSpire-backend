from flask import Flask
from dotenv import load_dotenv  # ✅ Load env variables from .env file
import os

from app.routes.auth_routes import auth_bp
from app.routes.dashboard_routes import dashboard_bp
from app.routes.scan_routes import scan_bp

def create_app():
    # ✅ Load the .env file (important for JWT_SECRET_KEY)
    load_dotenv()

    app = Flask(__name__)

    # Optionally print JWT_SECRET_KEY to confirm it's loaded
    # print("Loaded JWT Secret:", os.getenv("JWT_SECRET_KEY"))

    # Register routes
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(dashboard_bp, url_prefix="/api/dashboard")
    app.register_blueprint(scan_bp, url_prefix="/api/scan")

    return app
