from services.fw_service import FwService
from panos.objects import AddressGroup, AddressObject as PanAddressObject
from app import app
import traceback

def inspect_fw_data():
    with app.app_context():
        print("--- Inspecting Live Firewall Data ---")
        try:
            fw = FwService.get_connection()
            print(f"Connected to FW: {fw.hostname}")
            
            print("Fetching Address Objects...")
            addrs = PanAddressObject.refreshall(fw)
            addr_names = {a.name.lower() for a in addrs}
            print(f"Fetched {len(addrs)} addresses.")
            
            print("Fetching Address Groups...")
            groups = AddressGroup.refreshall(fw)
            print(f"Fetched {len(groups)} groups.")
            
            count_with_members = 0
            for g in groups:
                data = g.about()
                members = data.get('static') or data.get('static_value')
                if members:
                    count_with_members += 1
                    print(f"Group '{g.name}' members: {members}")
                    
                    # Verify integrity
                    missing = [m for m in members if m.lower() not in addr_names]
                    if missing:
                        print(f"  WARNING: Members NOT found in Address Objects: {missing}")
                    else:
                        print(f"  OK: All members found in Address Objects.")
                        
                    if count_with_members >= 5: break
                
        except Exception as e:
            print("ERROR:")
            traceback.print_exc()

if __name__ == "__main__":
    inspect_fw_data()
