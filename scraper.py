import requests
import pandas as pd
from bs4 import BeautifulSoup
import json
import os
from datetime import datetime

# Headers to mimic a real browser and avoid basic blocks
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
}

def fetch_fastag_data():
    """Fetches NETC FASTag Volume and Value from NPCI"""
    print("Fetching FASTag Data...")
    url = "https://www.npci.org.in/what-we-do/netc-fastag/product-statistics"
    try:
        response = requests.get(url, headers=HEADERS, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # NOTE: NPCI updates their table structures. 
        # You will need to inspect the live table to get the exact class/ID.
        # This extracts the first table found on the stats page.
        tables = pd.read_html(response.text)
        if tables:
            df = tables[0] 
            # Process dataframe to get the latest month's data
            latest_month_data = df.iloc[0].to_dict()
            return {
                "metric": "FASTag Logistics",
                "latest_volume": latest_month_data.get("Volume (in Mn)", 0),
                "latest_value_cr": latest_month_data.get("Value (in Cr)", 0),
                "status": "Success"
            }
    except Exception as e:
        print(f"FASTag Scraping Error: {e}")
        return {"metric": "FASTag Logistics", "status": "Failed", "error": str(e)}

def fetch_port_freight_data():
    """Fetches Major Ports Cargo Traffic (Commodity Wise) from IPA"""
    print("Fetching Port Freight Data...")
    # IPA often uploads Excel files for monthly traffic. 
    # A robust scraper would find the latest PDF/Excel link on the IPA site and parse it.
    # For this example, we structure how the processed data should look for your widget.
    
    # Real implementation requires using PyPDF2 or pandas read_excel on the downloaded IPA report.
    return {
        "metric": "Port Cargo Traffic",
        "commodities": {
            "Iron_Ore": {"growth_yoy_percent": 14.2, "implied_sector": "Steel"},
            "Thermal_Coal": {"growth_yoy_percent": 8.5, "implied_sector": "Power"},
            "Petroleum_POL": {"growth_yoy_percent": -2.1, "implied_sector": "Oil & Gas"}
        },
        "status": "Simulated Logic for Target File Structure"
    }

def main():
    # 1. Gather Data
    fastag_data = fetch_fastag_data()
    port_data = fetch_port_freight_data()
    
    # 2. Compile Widget JSON (This goes to your App)
    widget_payload = {
        "last_updated": datetime.utcnow().isoformat(),
        "signals": {
            "logistics_momentum": fastag_data,
            "commodity_freight": port_data,
        },
        "sector_strength_ranking": [
            {"sector": "Steel & Metals", "momentum": "High", "catalyst": "Iron Ore Port Traffic Up"},
            {"sector": "Power & Energy", "momentum": "High", "catalyst": "Thermal Coal Freight Up"},
            {"sector": "Logistics", "momentum": "Moderate", "catalyst": "FASTag Volumes Stable"}
        ]
    }
    
    # 3. Save to File
    output_file = "macro_data.json"
    with open(output_file, 'w') as f:
        json.dump(widget_payload, f, indent=4)
    
    print(f"Data successfully saved to {output_file}")

if __name__ == "__main__":
    main()
