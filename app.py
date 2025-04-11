from flask import Flask, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from apscheduler.schedulers.background import BackgroundScheduler
import requests
import os

app = Flask(__name__)
CORS(app)

# Rate limiting: 10 req/min per IP
limiter = Limiter(get_remote_address, app=app, default_limits=["10 per minute"])

# Store Angel One data here
cached_data = {
    "gainers_losers": [],
    "pcr": [],
    "oi_buildup": []
}

# Fetch function – every 5 min
def fetch_data():
    print("⏰ Fetching Angel One data...")

    headers = {
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

    # 1. Gainers/Losers
    try:
        body = {
            "datatype": "PercPriceGainers",
            "expirytype": "NEAR"
        }
        res = requests.post("https://apiconnect.angelone.in/rest/secure/angelbroking/marketData/v1/gainersLosers",
                            json=body, headers=headers)
        cached_data["gainers_losers"] = res.json().get("data", [])
    except Exception as e:
        print("Error fetching gainers/losers:", e)

    # 2. PCR
    try:
        res = requests.get("https://apiconnect.angelone.in/rest/secure/angelbroking/marketData/v1/putCallRatio",
                           headers=headers)
        cached_data["pcr"] = res.json().get("data", [])
    except Exception as e:
        print("Error fetching PCR:", e)

    # 3. OI Buildup
    try:
        body = {
            "expirytype": "NEAR",
            "datatype": "Long Built Up"
        }
        res = requests.post("https://apiconnect.angelone.in/rest/secure/angelbroking/marketData/v1/OIBuildup",
                            json=body, headers=headers)
        cached_data["oi_buildup"] = res.json().get("data", [])
    except Exception as e:
        print("Error fetching OI Buildup:", e)

# Run scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(func=fetch_data, trigger="interval", minutes=5)
scheduler.start()

@app.route("/gainers-losers", methods=["GET"])
@limiter.limit("5 per minute")
def gainers_losers():
    return jsonify(cached_data["gainers_losers"])

@app.route("/pcr", methods=["GET"])
@limiter.limit("5 per minute")
def pcr_data():
    return jsonify(cached_data["pcr"])

@app.route("/oi-buildup", methods=["GET"])
@limiter.limit("5 per minute")
def oi_buildup_data():
    return jsonify(cached_data["oi_buildup"])

if __name__ == "__main__":
    fetch_data()  # Run once at startup
    app.run(debug=True)
