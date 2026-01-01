from app import app
from services.fw_service import FwService
from managers.models import SecurityRule

with app.app_context():
    # 1. Inspect DB Rules
    print("--- Inspecting DB Rules ---")
    rules = SecurityRule.query.all()
    if not rules:
        print("NO RULES IN DB!")
    else:
        print(f"Found {len(rules)} rules.")
        r = rules[0]
        print(f"Sample Rule: {r.name}, Src: {[s.name for s in r.sources]}, Dst: {[d.name for d in r.destinations]}, Svc: {[s.name for s in r.services]}")

    # 2. Test Flatten Logic
    print("\n--- Testing Flatten & Zone ---")
    # Replace with a known IP from the user's previous screenshot if possible, or common ones
    test_src = "192.168.20.219" 
    src_set = FwService.flatten_address(test_src)
    print(f"Flatten '{test_src}': {src_set}")
    
    zone = FwService.detect_zone(test_src)
    print(f"Detected Zone for '{test_src}': {zone}")

    # 3. Test Shadow Check logic directly
    print("\n--- Running Shadow Check ---")
    # Try to shadow the sample rule found above
    if rules:
        r = rules[0]
        s_name = r.sources[0].name
        d_name = r.destinations[0].name
        svc_name = r.services[0].name
        print(f"Checking exact match for: Src={s_name}, Dst={d_name}, Svc={svc_name}")
        
        res = FwService.check_shadow_rule(
            source=s_name, 
            dest=d_name, 
            from_zone='any', # Try valid zones if known
            to_zone='any',
            service_port=svc_name
        )
        print(f"Result: {res}")
    else:
        print("Skipping Shadow Check test (no rules).")
