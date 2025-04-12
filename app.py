from flask import Flask, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from apscheduler.schedulers.background import BackgroundScheduler
import requests
import os
import atexit
import logging
import json
import pyotp
from dotenv import load_dotenv
from SmartApi.smartConnect import SmartConnect

# Load environment variables from .env
load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AngelOneAPI")

# Flask setup
app = Flask(__name__)
CORS(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["10 per minute"])

# In-memory cache
cached_data = {
    "gainers_losers": [],
    "pcr": [],
    "oi_buildup": []
}

# Login function to get JWT token
def login_and_set_token():
    api_key = os.getenv("ANGEL_API_KEY")
    client_id = os.getenv("ANGEL_CLIENT_ID")
    password = os.getenv("ANGEL_PASSWORD")
    totp_secret = os.getenv("ANGEL_TOTP_SECRET")

    if not all([api_key, client_id, password, totp_secret]):
        logger.error("❌ Missing environment variables for Angel login.")
        return None

    logger.info("🔐 Logging in to Angel One...")
    try:
        obj = SmartConnect(api_key=api_key)
        totp = pyotp.TOTP(totp_secret).now()
        data = obj.generateSession(client_id, password, totp)

        jwt_token = data["data"]["jwtToken"]
        feed_token = obj.getfeedToken()

        os.environ["ANGEL_JWT_TOKEN"] = jwt_token
        os.environ["ANGEL_FEED_TOKEN"] = feed_token

        logger.info("✅ Login successful.")
        return jwt_token
    except Exception as e:
        logger.error(f"❌ Login failed: {e}")
        return None

# Build headers with correct API key
def get_headers():
    jwt_token = os.getenv("ANGEL_JWT_TOKEN")
    api_key = os.getenv("ANGEL_API_KEY")  # Use API key here, not client ID

    return {
        "Authorization": f"Bearer {jwt_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "X-ClientLocalIP": "127.0.0.1",
        "X-ClientPublicIP": "127.0.0.1",
        "X-MACAddress": "AA:BB:CC:DD:EE:FF",
        "X-PrivateKey": api_key
    }

# Main function to fetch data
def fetch_data():
    logger.info("🔄 Fetching Angel One data...")
    login_and_set_token()
    headers = get_headers()

    endpoints = {
        "gainers_losers": {
            "url": "https://apiconnect.angelone.in/rest/secure/angelbroking/marketData/v1/gainersLosers",
            "body": {"datatype": "PercPriceGainers", "expirytype": "NEAR"},
            "method": "POST"
        },
        "pcr": {
            "url": "https://apiconnect.angelone.in/rest/secure/angelbroking/marketData/v1/putCallRatio",
            "body": None,
            "method": "GET"
        },
        "oi_buildup": {
            "url": "https://apiconnect.angelone.in/rest/secure/angelbroking/marketData/v1/OIBuildup",
            "body": {"expirytype": "NEAR", "datatype": "Long Built Up"},
            "method": "POST"
        }
    }

    for key, config in endpoints.items():
        try:
            logger.info(f"📡 Fetching: {key.replace('_', ' ').title()}")
            if config["method"] == "POST":
                response = requests.post(config["url"], headers=headers, json=config["body"])
            else:
                response = requests.get(config["url"], headers=headers)

            if response.status_code == 200:
                data = response.json().get("data", [])
                cached_data[key] = data
                logger.info(f"✅ {key.replace('_', ' ').title()} updated. Count: {len(data)}")
                if not data:
                    logger.warning(f"⚠️ {key} is empty:\n{json.dumps(response.json(), indent=2)}")
            else:
                logger.error(f"❌ Failed to fetch {key}. Status: {response.status_code}")
                logger.error(f"Response Body: {response.text}")
        except Exception as e:
            logger.error(f"❌ Exception during {key} fetch: {e}")

# Scheduler to run fetch_data every few minutes
interval = int(os.getenv("SCHEDULER_INTERVAL_MINUTES", 5))
scheduler = BackgroundScheduler()
scheduler.add_job(fetch_data, trigger="interval", minutes=interval)
scheduler.start()
atexit.register(lambda: scheduler.shutdown())

# Routes
@app.route("/")
def index():
    return jsonify({"status": "running", "message": "Angel One API server is live!"})

@app.route("/api/gainers-losers")
@limiter.limit("5 per minute")
def get_gainers_losers():
    return jsonify({"status": "success", "data": cached_data["gainers_losers"]})

@app.route("/api/pcr")
@limiter.limit("5 per minute")
def get_pcr():
    return jsonify({"status": "success", "data": cached_data["pcr"]})

@app.route("/api/oi-buildup")
@limiter.limit("5 per minute")
def get_oi_buildup():
    return jsonify({"status": "success", "data": cached_data["oi_buildup"]})

# Initial fetch on startup
fetch_data()

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True)
