from app import app
from managers.models import db_sql
from services.fw_service import FwService
from services.sync_service import SyncService
from panos.objects import AddressObject, AddressGroup, ServiceObject, ServiceGroup
from panos.policies import SecurityRule, Rulebase
from datetime import datetime

with app.app_context():
    print("Connecting to Firewall...")
    fw = FwService.get_connection()
    rb = Rulebase()
    fw.add(rb)

    print("Fetching raw data via panos SDK...")
    addr_objs = AddressObject.refreshall(fw)
    addr_groups = AddressGroup.refreshall(fw)
    svc_objs = ServiceObject.refreshall(fw)
    svc_groups = ServiceGroup.refreshall(fw)
    rules_objs = SecurityRule.refreshall(rb)

    print(f"Fetched: {len(addr_objs)} Addresses, {len(rules_objs)} Rules.")

    # Fix apps list as in app.py
    found_apps = set()
    for r in rules_objs:
        apps = r.application
        if isinstance(apps, list): found_apps.update(apps)
        elif apps: found_apps.add(apps)
    
    apps_payload = [{"name": app, "description": "System", "is_group": False} 
                   for app in found_apps if app and app.lower() != 'any']

    fw_config = {
        'address': [obj.about() for obj in addr_objs],
        'address-group': [obj.about() for obj in addr_groups],
        'service': [obj.about() for obj in svc_objs],
        'service-group': [obj.about() for obj in svc_groups],
        'rules': [obj.about() for obj in rules_objs],
        'applications': apps_payload
    }

    print("Starting SyncManager...")
    sync_mgr = SyncService(fw)
    success = sync_mgr.sync_all(fw_config)
    
    if success:
        print("✅ Sync COMPLETED SUCCESSFULLY.")
    else:
        print("❌ Sync FAILED.")
