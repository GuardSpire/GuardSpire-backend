from flask import Flask
from dotenv import load_dotenv  # ✅ Load env variables from .env file
import os

from app.routes.auth_routes import auth_bp
from app.routes.dashboard_routes import dashboard_bp
from app.routes.scan_routes import scan_bp
from app.routes.account_routes import account_bp
from app.routes.delete_routes import delete_bp
from flask_cors import CORS

def create_app():
    # ✅ Load the .env file (important for JWT_SECRET_KEY)
    load_dotenv()

    app = Flask(__name__)

    CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

    # Optionally print JWT_SECRET_KEY to confirm it's loaded
    # print("Loaded JWT Secret:", os.getenv("JWT_SECRET_KEY"))

    # Register routes
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(dashboard_bp, url_prefix='/api/dashboard')
    app.register_blueprint(scan_bp, url_prefix='/api/scan')
    app.register_blueprint(account_bp, url_prefix='/api/account')
    app.register_blueprint(delete_bp, url_prefix='/api/delete')
    app.config['VIRUSTOTAL_API_KEY'] = os.getenv('VIRUSTOTAL_API_KEY')
    app.config['GOOGLE_SAFE_BROWSING_API_KEY'] = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')

        # Debug print
    print("✅ Registered Routes:")
    for rule in app.url_map.iter_rules():
        print(f"{rule.endpoint} → {rule.rule} [{', '.join(rule.methods)}]")

    return app
