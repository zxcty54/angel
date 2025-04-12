import os
import time
import json
import requests
import pyotp
import dotenv
from flask import Flask, jsonify
from apscheduler.schedulers.background import BackgroundScheduler
import logging

# Load environment variables
dotenv.load_dotenv()

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Angel One credentials
API_KEY = os.getenv("ANGEL_API_KEY")
CLIENT_ID = os.getenv("ANGEL_CLIENT_ID")
PASSWORD = os.getenv("ANGEL_PASSWORD")
TOTP_SECRET = os.getenv("ANGEL_TOTP_SECRET")

# Token file path
TOKEN_FILE = "angel_jwt.token"

# Global storage for fetched data
latest_data = {}

app = Flask(__name__)


def get_saved_token():
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r") as f:
            return f.read().strip()
    return None


def save_token(jwt_token):
    with open(TOKEN_FILE, "w") as f:
        f.write(jwt_token)


def generate_totp():
    return pyotp.TOTP(TOTP_SECRET).now()


def login_and_get_token():
    logger.info("🔐 Logging in to Angel One...")
    url = "https://apiconnect.angelone.in/rest/auth/angelbroking/user/v1/loginByPassword"

    payload = {
        "clientcode": CLIENT_ID,
        "password": PASSWORD,
        "totp": generate_totp()
    }

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "X-ClientLocalIP": "127.0.0.1",
        "X-ClientPublicIP": "127.0.0.1",
        "X-MACAddress": "00:00:00:00:00:00",
        "X-PrivateKey": API_KEY
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 200:
            jwt_token = response.json().get("data", {}).get("jwtToken")
            if jwt_token:
                logger.info(f"✅ JWT Token: {jwt_token}")  # Log the token
                save_token(jwt_token)
                return jwt_token
            else:
                logger.error("❌ JWT token missing in response.")
        else:
            logger.error(f"❌ Login failed: {response.status_code} - {response.text}")
    except Exception as e:
        logger.exception("❌ Exception during login:")
    return None


def get_valid_token():
    jwt_token = get_saved_token()
    if not jwt_token:
        jwt_token = login_and_get_token()
    return jwt_token


def fetch_data():
    global latest_data
    jwt_token = get_valid_token()

    if not jwt_token:
        logger.error("❌ Cannot fetch data without a valid token.")
        return

    url = "https://apiconnect.angelone.in/rest/secure/angelbroking/order/v1/getLtpData"
    payload = {
        "exchange": "NSE",
        "tradingsymbol": "RELIANCE-EQ",
        "symboltoken": "2885"
    }

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "X-ClientLocalIP": "127.0.0.1",
        "X-ClientPublicIP": "127.0.0.1",
        "X-MACAddress": "00:00:00:00:00:00",
        "X-PrivateKey": API_KEY,
        "Authorization": f"Bearer {jwt_token}"
    }

    try:
        logger.info(f"⏳ Fetching data from API: {url}")
        response = requests.post(url, json=payload, headers=headers)

        # Handle token expiry
        if response.status_code == 401 or "Invalid Token" in response.text:
            logger.warning("⚠️ Token expired. Re-logging in...")
            jwt_token = login_and_get_token()
            if jwt_token:
                headers["Authorization"] = f"Bearer {jwt_token}"
                response = requests.post(url, json=payload, headers=headers)

        if response.status_code == 200:
            latest_data = response.json()
            logger.info(f"📈 Fetched data: {json.dumps(latest_data, indent=4)}")  # Pretty print the data
        else:
            logger.error(f"❌ Failed to fetch data: {response.status_code} - {response.text}")
    except Exception as e:
        logger.exception("❌ Exception during data fetch:")


@app.route("/")
def home():
    return jsonify(latest_data or {"message": "No data available yet"})


if __name__ == "__main__":
    fetch_data()  # Initial fetch on app start
    scheduler = BackgroundScheduler()
    scheduler.add_job(fetch_data, "interval", minutes=5)
    scheduler.start()
    app.run(debug=False, port=5000)
