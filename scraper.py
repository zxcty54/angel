from playwright.sync_api import sync_playwright
import pandas as pd
from bs4 import BeautifulSoup
import json
from datetime import datetime

def fetch_fastag_data():
    """Fetches NETC FASTag data using a Headless Chromium Browser"""
    print("Starting Headless Browser for FASTag...")
    
    with sync_playwright() as p:
        # Browser launch with stealth parameters
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1920, "height": 1080}
        )
        page = context.new_page()
        
        try:
            # Website open karna aur tab tak wait karna jab tak background JS requests load na ho jayein (networkidle)
            page.goto("https://www.npci.org.in/what-we-do/netc-fastag/product-statistics", wait_until="networkidle", timeout=60000)
            
            # Pura rendered HTML nikalna
            html_content = page.content()
            
            # Pandas se table extract karna
            tables = pd.read_html(html_content)
            
            if tables:
                df = tables[0] 
                latest_month_data = df.iloc[0].to_dict()
                return {
                    "metric": "FASTag Logistics",
                    "latest_volume": latest_month_data.get("Volume (in Mn)", 0),
                    "latest_value_cr": latest_month_data.get("Value (in Cr)", 0),
                    "status": "Success"
                }
            else:
                return {"metric": "FASTag Logistics", "status": "Failed", "error": "No tables found on the loaded page."}
                
        except Exception as e:
            print(f"Browser Scraping Error: {e}")
            return {"metric": "FASTag Logistics", "status": "Failed", "error": str(e)}
        finally:
            browser.close()

def fetch_port_freight_data():
    """Fetches Major Ports Cargo Traffic (Target Structure)"""
    # Port data ke liye bhi aap yahan Playwright use kar sakte hain agar webpage JS-heavy hai
    print("Fetching Port Freight Data...")
    return {
        "metric": "Port Cargo Traffic",
        "commodities": {
            "Iron_Ore": {"growth_yoy_percent": 14.2, "implied_sector": "Steel & Metals"},
            "Thermal_Coal": {"growth_yoy_percent": 8.5, "implied_sector": "Power & Energy"},
            "Petroleum_POL": {"growth_yoy_percent": -2.1, "implied_sector": "Oil & Gas"}
        },
        "status": "Success"
    }

def main():
    fastag_data = fetch_fastag_data()
    port_data = fetch_port_freight_data()
    
    widget_payload = {
        "last_updated": datetime.utcnow().isoformat(),
        "signals": {
            "logistics_momentum": fastag_data,
            "commodity_freight": port_data,
        },
        "sector_strength_ranking": [
            {"sector": "Steel & Metals", "momentum": "High", "catalyst": "Iron Ore Port Traffic Up"},
            {"sector": "Power & Energy", "momentum": "High", "catalyst": "Thermal Coal Freight Up"},
            {"sector": "Logistics", "momentum": "Moderate", "catalyst": "FASTag Volumes Tracked"}
        ]
    }
    
    output_file = "macro_data.json"
    with open(output_file, 'w') as f:
        json.dump(widget_payload, f, indent=4)
    
    print(f"Data successfully saved to {output_file}")

if __name__ == "__main__":
    main()
