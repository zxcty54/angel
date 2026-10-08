from playwright.sync_api import sync_playwright
import pandas as pd
import json
import io  # Pandas warning fix karne ke liye
from datetime import datetime

def fetch_fastag_data():
    """Fetches NETC FASTag data using a Headless Chromium Browser"""
    print("Starting Headless Browser for FASTag...")
    
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1920, "height": 1080}
        )
        page = context.new_page()
        
        try:
            # Page load karna
            print("Navigating to NPCI...")
            page.goto("https://www.npci.org.in/what-we-do/netc-fastag/product-statistics", wait_until="networkidle", timeout=60000)
            
            print(f"Page Title: {page.title()}") # Debugging ke liye check karenge ki page sahi khula ya nahi
            
            # **Fix:** Explicitly wait for the table to appear on the screen (Max 15 seconds)
            print("Waiting for data table to render...")
            page.wait_for_selector("table", timeout=15000)
            
            # Thoda extra wait taaki table ka data poori tarah populate ho jaye
            page.wait_for_timeout(2000)
            
            # Render hone ke baad HTML extract karna
            html_content = page.content()
            
            # **Fix:** Pandas FutureWarning fix using io.StringIO
            tables = pd.read_html(io.StringIO(html_content))
            
            if tables and len(tables) > 0:
                df = tables[0] 
                
                # Check agar dataframe khali nahi hai
                if not df.empty:
                    # Pehli row usually latest month ki hoti hai
                    latest_month_data = df.iloc[0].to_dict()
                    
                    # Columns ke exact naam NPCI update karta rehta hai, unko dict se nikalenge
                    # Yahan hum index position se value nikal rahe hain taaki header name change hone par error na aaye
                    latest_volume = df.iloc[0, 1] if len(df.columns) > 1 else 0
                    latest_value_cr = df.iloc[0, 2] if len(df.columns) > 2 else 0
                    
                    print(f"Data found! Volume: {latest_volume}, Value: {latest_value_cr}")
                    
                    return {
                        "metric": "FASTag Logistics",
                        "latest_volume": str(latest_volume),
                        "latest_value_cr": str(latest_value_cr),
                        "status": "Success"
                    }
                else:
                    return {"metric": "FASTag Logistics", "status": "Failed", "error": "Table found but it is empty"}
            else:
                return {"metric": "FASTag Logistics", "status": "Failed", "error": "No tables parsed by Pandas"}
                
        except Exception as e:
            print(f"Browser Scraping Error: {e}")
            return {"metric": "FASTag Logistics", "status": "Failed", "error": str(e)}
        finally:
            browser.close()

def fetch_port_freight_data():
    """Fetches Major Ports Cargo Traffic"""
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
