from app import app
from managers.models import db_sql, AddressObject, SecurityRule
from routes.ops_routes import resolve_object_content

with app.app_context():
    print("--- Checking Address Objects (First 10) ---")
    objs = AddressObject.query.limit(10).all()
    for o in objs:
        content = resolve_object_content(o)
        print(f"Name: {o.name:<20} | Type: {o.type:<10} | Value: {o.value:<20} | IsGroup: {o.is_group} | Resolved: {content}")

    print("\n--- Checking Security Rules Sources Resolution (First 5 Rules) ---")
    rules = SecurityRule.query.limit(5).all()
    for r in rules:
        print(f"Rule: {r.name}")
        for s in r.sources:
             content = resolve_object_content(s)
             print(f"  Source: {s.name:<20} | Value: {s.value} | Resolved: {content}")
