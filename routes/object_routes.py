from flask import Blueprint, request, jsonify, session
from schemas.objects import AddressObjectCreate, ServiceObjectCreate
from services.object_service import ObjectService
from managers.models import ObjectRequest, AddressObject, ServiceObject
try:
    from pydantic import ValidationError
except ImportError:
    # Fallback to standard error if pydantic not explicitly available in some context
    ValidationError = ValueError 

objects_bp = Blueprint('objects', __name__)

def get_user():
    return session.get('user', 'Unknown')

@objects_bp.route('/create-object', methods=['POST'])
def create_object_request():
    try:
        # 1. Validation Logic (Strict)
        data = request.json
        obj_type = data.get('type')
        
        # Dispatch to correct Pydantic Schema
        if 'address' in obj_type:
            validated = AddressObjectCreate(**data)
        elif 'service' in obj_type:
            validated = ServiceObjectCreate(**data)
        else:
            return jsonify({"status": "error", "message": "Invalid object type"}), 400
            
        # 2. Service Logic
        ObjectService.create_request(validated, get_user())
        
        return jsonify({"status": "success", "message": "Object request created successfully"})
        
    except ValidationError as e:
        # Return precise Pydantic errors
        return jsonify({"status": "error", "message": str(e)}), 422
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": "System Error"}), 500

@objects_bp.route('/approve-object/<int:obj_id>', methods=['POST'])
def approve_object(obj_id):
    if not session.get('is_admin'): return jsonify({"message": "Unauthorized"}), 403
    try:
        ObjectService.approve_request(obj_id, get_user())
        return jsonify({"status": "success", "message": "Object approved & created on Firewall"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@objects_bp.route('/reject-object/<int:obj_id>', methods=['POST'])
def reject_object(obj_id):
    if not session.get('is_admin'): return jsonify({"message": "Unauthorized"}), 403
    try:
        reason = request.json.get('reason', 'Admin rejected')
        ObjectService.reject_request(obj_id, get_user(), reason)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@objects_bp.route('/update-pending-object/<int:obj_id>', methods=['POST'])
def update_pending_object(obj_id):
    if not session.get('is_admin'): return jsonify({"message": "Unauthorized"}), 403
    try:
        # We pass raw dict here or validate partial
        ObjectService.update_request(obj_id, request.json, get_user())
        return jsonify({"status": "success", "message": "Object updated"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# Read-only routes (Direct DB access is fine for simple reads, or move to Service)
@objects_bp.route('/get-admin-view-objects')
def get_admin_objects():
    if not session.get('is_admin'): return jsonify({"message": "Unauthorized"}), 403
    reqs = ObjectRequest.query.order_by(ObjectRequest.id.desc()).all()
    return jsonify([{
        "id": r.id, "name": r.name, "value": r.value, "type": r.obj_type,
        "status": r.status, "requested_by": r.requested_by,
        "time": r.request_time.strftime("%Y-%m-%d %H:%M") if r.request_time else ""
    } for r in reqs])

@objects_bp.route('/get-my-objects')
def get_my_objects():
    reqs = ObjectRequest.query.filter_by(requested_by=get_user()).order_by(ObjectRequest.id.desc()).all()
    # Serialize logic same as above
    return jsonify([{
        "id": r.id, "name": r.name, "value": r.value, "type": r.obj_type,
        "status": r.status
    } for r in reqs])

@objects_bp.route('/get-address-objects')
def get_address_objects_list():
    objs = AddressObject.query.filter_by(is_group=False).all()
    return jsonify({"status": "success", "addresses": sorted([o.name for o in objs])})

@objects_bp.route('/get-service-objects')
def get_service_objects_list():
    objs = ServiceObject.query.filter_by(is_group=False).all()
    return jsonify({"status": "success", "services": sorted([o.name for o in objs])})