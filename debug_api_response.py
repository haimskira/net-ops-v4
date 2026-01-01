from app import app
from managers.models import SecurityRule, AddressObject, ServiceObject
from sqlalchemy.orm import joinedload, selectinload
from services.fw_service import FwService # for resolve_object_content dependency if needed
import json

# Re-implement helper (copy from ops_routes.py because we can't easily import it if it's inside a route file context without Flask)
def resolve_object_content(obj, depth=0):
    if not obj or depth > 5: return []
    if not getattr(obj, 'is_group', False):
        val = getattr(obj, 'value', '') or getattr(obj, 'port', '')
        if val and str(val).lower() not in ['any', 'group', 'application-default']:
            return [str(val)]
        return []
    res = []
    members = getattr(obj, 'members', [])
    for m in members:
        res.extend(resolve_object_content(m, depth + 1))
    return list(set(res))

def debug_api():
    with app.app_context():
        print(f"DB URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
        print("--- Simulating get_all_policies API (Lazy Loading) ---")
        
        # 1. Fetch Rules (Lazy)
        rules = SecurityRule.query.all()
        print(f"Fetched {len(rules)} rules.")
        
        # 2. Logic Check
        found_group = False
        for r in rules[:10]: # Check first 10 rules
            for o in r.sources:
                if getattr(o, 'is_group', False):
                    found_group = True
                    print(f"\nRule '{r.name}' has Source Group: '{o.name}' (ID: {o.id})")
                    
                    # Manual Member Access (Triggers Lazy Load)
                    count = len(o.members)
                    print(f"  - DB Members Count (Lazy): {count}")
                    if count > 0:
                        print(f"  - First Member: {o.members[0].name}")
                    else:
                        print("  - WARNING: Members count is 0!")

                    # Recursive Expansion Simulation
                    expanded = []
                    seen = set()
                    def add_obj(obj_to_add):
                        if obj_to_add.name in seen: return
                        seen.add(obj_to_add.name)
                        tech_vals = resolve_object_content(obj_to_add)
                        expanded.append({
                            "name": obj_to_add.name,
                            "value": ", ".join(tech_vals) if tech_vals else obj_to_add.name,
                            "is_group": getattr(obj_to_add, 'is_group', False)
                        })

                    def expand_group(obj):
                        if getattr(obj, 'is_group', False):
                            if obj.members:
                                for m in obj.members:
                                    expand_group(m)
                            else:
                                print(f"  - Fallback: Adding empty group {obj.name}")
                                add_obj(obj)
                        else:
                            add_obj(obj)

                    expand_group(o)
                    # print(f"  - Expanded Output: {json.dumps(expanded, indent=2)}") 
                        
                    print(f"  - Expanded Output: {json.dumps(expanded, indent=2)}")
                    if len(expanded) == 0:
                         print("  CRITICAL: Expanded output is EMPTY!")
                    elif expanded[0]['name'] == o.name and len(o.members) > 0:
                         print("  CRITICAL: Logic returned Group Name instead of Members!")

        if not found_group:
            print("No rules with Source Groups found in first 50 rules. Trying to find ANY rule with a group...")
            # Try to find a rule that definitely has a group
            # Find a group with members first
            g = AddressObject.query.filter_by(is_group=True).filter(AddressObject.members.any()).first()
            if g:
                 print(f"Found valid group '{g.name}' with {len(g.members)} members.")
                 # Find rule using it
                 # This is hard via SQLA reverse lookup without backref fully set up, but let's try
                 print("Checking if it's used in any rule...")
                 # Manual check not easy efficiently, skipping.
            else:
                 print("Could not find any non-empty group in DB via query.")

if __name__ == "__main__":
    debug_api()
