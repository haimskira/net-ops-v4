from managers.fw_manager import get_fw_connection
from panos.objects import AddressObject

try:
    print("Connecting to Firewall...")
    fw = get_fw_connection()
    print("Fetching Address Objects...")
    objs = AddressObject.refreshall(fw)
    
    if objs:
        print(f"\n--- Found {len(objs)} objects. Showing first 3 details ---")
        for i, obj in enumerate(objs[:3]):
            print(f"\nObject {i+1}: {obj.name}")
            print(f"Raw .about() output: {obj.about()}")
            print(f"Direct value attribute: {getattr(obj, 'value', 'N/A')}")
    else:
        print("No address objects found.")

except Exception as e:
    print(f"Error: {e}")
