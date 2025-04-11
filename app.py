from flask import Flask, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from apscheduler.schedulers.background import BackgroundScheduler
import requests
import os
import atexit
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Rate limit: 10 requests per minute per IP
limiter = Limiter(get_remote_address, app=app, default_limits=["10 per minute"])

# Cache to store responses
cached_data = {
    "gainers_losers": [],
    "pcr": [],
    "oi_buildup": []
}

# Angel One API headers
def get_headers():
    access_token = os.getenv("ANGEL_ACCESS_TOKEN", "").strip()
    client_id = os.getenv("ANGEL_CLIENT_ID", "").strip()
    
    logger.info(f"Using ANGEL_ACCESS_TOKEN: {'SET' if access_token else 'MISSING'}")
    logger.info(f"Using ANGEL_CLIENT_ID: {'SET' if client_id else 'MISSING'}")

    return {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "X-ClientLocalIP": "127.0.0.1",
        "X-ClientPublicIP": "127.0.0.1",
        "X-MACAddress": "AA:BB:CC:DD:EE:FF",
        "X-PrivateKey": client_id
    }

# Fetch data every 5 minutes
def fetch_data():
    logger.info("🔄 Fetching Angel One data...")

    headers = get_headers()

    # Gainers/Losers
    try:
        body = {"datatype": "PercPriceGainers", "expirytype": "NEAR"}
        r = requests.post("https://apiconnect.angelone.in/rest/secure/angelbroking/marketData/v1/gainersLosers",
                          json=body, headers=headers)
        logger.info("📈 Gainers/Losers Status Code: %s", r.status_code)
        logger.info("📈 Gainers/Losers Raw Response: %s", r.text)

        cached_data["gainers_losers"] = r.json().get("data", [])
        logger.info("✅ Gainers/Losers updated. Count: %d", len(cached_data["gainers_losers"]))
    except Exception as e:
        logger.error("❌ Gainers/Losers error: %s", str(e))

    # Put Call Ratio (PCR)
    try:
        r = requests.get("https://apiconnect.angelone.in/rest/secure/angelbroking/marketData/v1/putCallRatio",
                         headers=headers)
        logger.info("📊 PCR Status Code: %s", r.status_code)
        logger.info("📊 PCR Raw Response: %s", r.text)

        cached_data["pcr"] = r.json().get("data", [])
        logger.info("✅ PCR updated. Count: %d", len(cached_data["pcr"]))
    except Exception as e:
        logger.error("❌ PCR error: %s", str(e))

    # OI Buildup
    try:
        body = {"expirytype": "NEAR", "datatype": "Long Built Up"}
        r = requests.post("https://apiconnect.angelone.in/rest/secure/angelbroking/marketData/v1/OIBuildup",
                          json=body, headers=headers)
        logger.info("📊 OI Buildup Status Code: %s", r.status_code)
        logger.info("📊 OI Buildup Raw Response: %s", r.text)

        cached_data["oi_buildup"] = r.json().get("data", [])
        logger.info("✅ OI Buildup updated. Count: %d", len(cached_data["oi_buildup"]))
    except Exception as e:
        logger.error("❌ OI Buildup error: %s", str(e))

# Background scheduler setup
scheduler = BackgroundScheduler()
scheduler.add_job(func=fetch_data, trigger="interval", minutes=5)
scheduler.start()
atexit.register(lambda: scheduler.shutdown())

# API Routes
@app.route("/")
def home():
    return jsonify({"status": "running", "message": "Angel One API server is live!"})

@app.route("/gainers-losers")
@limiter.limit("5 per minute")
def gainers_losers():
    return jsonify(cached_data["gainers_losers"])

@app.route("/pcr")
@limiter.limit("5 per minute")
def pcr():
    return jsonify(cached_data["pcr"])

@app.route("/oi-buildup")
@limiter.limit("5 per minute")
def oi_buildup():
    return jsonify(cached_data["oi_buildup"])

# Initial data fetch
fetch_data()

# Run Flask app
if __name__ == "__main__":
    app.run(debug=True)
