from flask import Flask, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from apscheduler.schedulers.background import BackgroundScheduler
import requests
import os
import atexit

app = Flask(__name__)
CORS(app)

# Limit: 10 requests per minute per IP
limiter = Limiter(get_remote_address, app=app, default_limits=["10 per minute"])

# Store latest Angel One API data
cached_data = {
    "gainers_losers": [],
    "pcr": [],
    "oi_buildup": []
}

# API HEADERS using environment variables
def get_headers():
    return {
        "Authorization": f"Bearer {os.getenv('ANGEL_TOKEN')}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "X-ClientLocalIP": "127.0.0.1",
        "X-ClientPublicIP": "127.0.0.1",
        "X-MACAddress": "AA:BB:CC:DD:EE:FF",
        "X-PrivateKey": os.getenv("CLIENT_CODE")
    }

# ⏰ Scheduled fetch function (every 5 minutes)
def fetch_data():
    print("⏳ Fetching fresh Angel One data...")

    headers = get_headers()

    # Gainers/Losers
    try:
        body = { "datatype": "PercPriceGainers", "expirytype": "NEAR" }
        r = requests.post("https://apiconnect.angelone.in/rest/secure/angelbroking/marketData/v1/gainersLosers", 
                          json=body, headers=headers)
        cached_data["gainers_losers"] = r.json().get("data", [])
        print("✅ Gainers/Losers updated")
    except Exception as e:
        print("❌ Error fetching gainers/losers:", e)

    # PCR (Put Call Ratio)
    try:
        r = requests.get("https://apiconnect.angelone.in/rest/secure/angelbroking/marketData/v1/putCallRatio", 
                         headers=headers)
        cached_data["pcr"] = r.json().get("data", [])
        print("✅ PCR updated")
    except Exception as e:
        print("❌ Error fetching PCR:", e)

    # OI Buildup
    try:
        body = { "expirytype": "NEAR", "datatype": "Long Built Up" }
        r = requests.post("https://apiconnect.angelone.in/rest/secure/angelbroking/marketData/v1/OIBuildup", 
                          json=body, headers=headers)
        cached_data["oi_buildup"] = r.json().get("data", [])
        print("✅ OI Buildup updated")
    except Exception as e:
        print("❌ Error fetching OI Buildup:", e)

# 🔁 Scheduler setup
scheduler = BackgroundScheduler()
scheduler.add_job(func=fetch_data, trigger="interval", minutes=5)
scheduler.start()

# Ensure scheduler stops on app exit
atexit.register(lambda: scheduler.shutdown())

# 🔥 Routes
@app.route("/")
def home():
    return jsonify({"status": "running", "message": "Angel API server is live!"})

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

# 🔁 Run one fetch at startup
@app.before_first_request
def initial_fetch():
    fetch_data()

# 🧪 Entry point
if __name__ == "__main__":
    app.run(debug=True)
