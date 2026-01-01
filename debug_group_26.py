from managers.models import AddressObject
from app import app

def debug_26():
    with app.app_context():
        g = AddressObject.query.filter_by(name='LAB-GROUP-26').first()
        if not g:
            print("Group LAB-GROUP-26 not found!")
            return
            
        print(f"Group: {g.name}")
        print(f"ID: {g.id}")
        print(f"Is Group: {g.is_group}")
        print(f"Members Count: {len(g.members)}")
        
        for m in g.members:
            print(f" - {m.name} (Group: {m.is_group}, Val: {m.value})")

if __name__ == "__main__":
    debug_26()
