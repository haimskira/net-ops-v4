from managers.models import db_sql, AddressObject, address_group_members
from app import app
from sqlalchemy import func

def verify_db():
    with app.app_context():
        print("--- Verifying Database Content ---")
        
        # 1. Count Total Objects
        addr_count = AddressObject.query.count()
        group_count = AddressObject.query.filter_by(is_group=True).count()
        print(f"Total Address Objects: {addr_count}")
        print(f"Total Groups: {group_count}")
        
        # 2. Check Association Table directly
        # method 1: count rows
        assoc_count = db_sql.session.query(address_group_members).count()
        print(f"Total Association Rows in 'address_group_members': {assoc_count}")
        
        if group_count > 0 and assoc_count == 0:
            print("CRITICAL: Groups exist but Association Table is EMPTY! Sync logic failed to link them.")
        
        # 3. Sample check
        groups = AddressObject.query.filter_by(is_group=True).limit(5).all()
        for g in groups:
            print(f"Group: {g.name}, Members in DB: {len(g.members)}")
            if g.members:
                print(f" -> {[m.name for m in g.members]}")

if __name__ == "__main__":
    verify_db()
