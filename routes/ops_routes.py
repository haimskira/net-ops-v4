"""
Expert Full-Stack Software Architecture: Operations & Monitoring Routes.
Handles Deep Object Resolution for Hover Tooltips and Smart Search.
Zero Truncation Policy: Full Functional File.
"""

# 1. Standard Library Imports
import logging
import time
import traceback
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Union
from datetime import datetime

# 2. Third-Party Library Imports
import requests
from flask import Blueprint, Response, jsonify, render_template, request, session
from sqlalchemy.orm import joinedload, selectinload  # הוספת selectinload לטעינת חברי קבוצה

# 3. Pan-OS / Firewall SDK Imports (Aliases to prevent SQLAlchemy conflicts)
from panos.network import Zone
from panos.objects import (
    AddressGroup as PanAddressGroup, 
    AddressObject as PanAddressObject, 
    ServiceObject as PanServiceObject, 
    ServiceGroup as PanServiceGroup,  # הוספת הייבוא החסר
    Tag as PanTag
)
from panos.policies import SecurityRule as PanSecurityRule, Rulebase

# 4. Local Application Imports (Project Specific)
from config import Config
from managers.data_manager import db # Keep if used for caching
from services.fw_service import FwService
from services.sync_service import SyncService
from managers.models import (
    AddressObject, 
    AuditLog, 
    SecurityRule, 
    ServiceObject, 
    ApplicationObject,
    TrafficLog, 
    db_sql,
    rule_app_map
)
# Sync service imported above

# Initialize the Ops Blueprint
ops_bp = Blueprint('ops', __name__)

def get_username():
    return session.get('user', 'Unknown')

# --------------------------------------------------------------------------
# I. Helper Functions (Deep Resolution Logic)
# --------------------------------------------------------------------------

def resolve_object_content(obj: Any, depth: int = 0) -> List[str]:
    """
    פונקציה רקורסיבית ששולפת את התוכן הטכני (IP/Port/App).
    מעודכנת לפתרון בעיית ה-ANY בקבוצות ע"י שליפה רקורסיבית של חברים.
    """
    if not obj or depth > 5: # הגנה מפני רקורסיה אינסופית
        return []
        
    if not getattr(obj, 'is_group', False):
        # שליפת הערך הטכני לפי סוג האובייקט
        val = getattr(obj, 'value', '') or getattr(obj, 'port', '')
        
        # סינון ערכים לא טכניים שעלולים להגיע מה-Firewall
        if val and str(val).lower() not in ['any', 'group', 'application-default']:
            return [str(val)]
        return []
    
    res = []
    # שליפת רשימת החברים מתוך הקשר (Relationship) - דורש Eager Loading בשאילתה
    members = getattr(obj, 'members', [])
    for m in members:
        res.extend(resolve_object_content(m, depth + 1))
        
    return list(set(res)) # הסרת כפילויות

# --------------------------------------------------------------------------
# II. View Routes (Template Rendering)
# --------------------------------------------------------------------------

@ops_bp.route('/log-viewer')
def log_viewer_page() -> str:
    """Renders the Live Traffic Log Viewer."""
    return render_template('log_viewer.html')

@ops_bp.route('/audit-logs')
def audit_logs_page() -> Union[str, Response]:
    """רק אדמין יכול לראות לוגי מערכת."""
    if not session.get('is_admin'):
        return render_template('error.html', message="Access to audit logs is reserved for administrators only"), 403
    try:
        logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(200).all()
        return render_template('audit.html', logs=logs)
    except Exception as e:
        logging.error(f"Audit Log Fetch Error: {str(e)}")
        return render_template('audit.html', logs=[])

@ops_bp.route('/policy-inventory')
def policy_inventory_page() -> str:
    """Renders the Firewall Policy Inventory dashboard (Open to all authenticated users)."""
    return render_template('policy_viewer.html')

# --------------------------------------------------------------------------
# III. API Routes - Logging (Database Driven)
# --------------------------------------------------------------------------

@ops_bp.route('/get-live-logs')
def get_live_logs() -> Response:
    """Fetches traffic logs from the dedicated logs database bind."""
    try:
        logs = TrafficLog.query.order_by(TrafficLog.id.desc()).limit(100).all()
        formatted = []
        for log in logs:
            formatted.append({
                "time": log.time,
                "source": log.source,
                "destination": log.destination,
                "src_zone": log.src_zone or 'N/A',
                "dst_zone": log.dst_zone or 'N/A',
                "app": log.app or 'any',
                "protocol": log.protocol or 'tcp',
                "dst_port": str(log.dst_port or 'any'),
                "action": log.action or 'allow'
            })
        return jsonify(formatted)
    except Exception as e:
        logging.error(f"API Log Fetch Error: {str(e)}")
        return jsonify([])

@ops_bp.route('/api/clear-logs', methods=['POST'])
def clear_logs() -> Response:
    """Clears the traffic logs table in the database (Admin only)."""
    if not session.get('is_admin'):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    try:
        db_sql.session.query(TrafficLog).delete()
        db_sql.session.commit()
        return jsonify({"status": "success"})
    except Exception as e:
        db_sql.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500


# --------------------------------------------------------------------------
# IV. API Routes - Inventory & Advanced Resolution
# --------------------------------------------------------------------------

@ops_bp.route('/get-all-policies')
def get_all_policies() -> Response:
    """
    שליפת חוקים עם טעינה עמוקה של חברי קבוצות למניעת באג ה-ANY.
    משתמש ב-selectinload כדי למשוך את ה-members של ה-ServiceObject וה-AddressObject.
    """
    try:
        # שימוש ב-JoinedLoad ו-SelectInLoad לפתרון בעיית חברי הקבוצות
        rules = SecurityRule.query.options(
            joinedload(SecurityRule.sources).selectinload(AddressObject.members),
            joinedload(SecurityRule.destinations).selectinload(AddressObject.members),
            joinedload(SecurityRule.services).selectinload(ServiceObject.members),
            joinedload(SecurityRule.applications)
        ).all()
        
        formatted_rules = []
        for r in rules:
            def format_collection(obj_list):
                if not obj_list: return []
                output = []
                for o in obj_list:
                    tech_vals = resolve_object_content(o)
                    output.append({
                        "name": o.name,
                        "value": ", ".join(tech_vals) if tech_vals else o.name,
                        "is_group": getattr(o, 'is_group', False)
                    })
                return output

            formatted_rules.append({
                "name": r.name,
                "from": r.from_zone or 'any',
                "to": r.to_zone or 'any',
                "sources": format_collection(r.sources),
                "destinations": format_collection(r.destinations),
                "services": format_collection(r.services),
                "applications": format_collection(r.applications),
                "action": r.action or 'allow'
            })
        return jsonify(formatted_rules)
    except Exception as e:
        logging.error(f"Inventory Fetch Error: {str(e)}")
        return jsonify([]), 500
    

@ops_bp.route('/get-params', methods=['GET'])
def get_params() -> Response:
    """Fetches metadata (Zones, Apps, Tags) with memory caching."""
    current_time = time.time()
    if not hasattr(db, 'firewall_cache'):
        db.firewall_cache = {"data": None, "last_updated": 0}

    if db.firewall_cache["data"] and (current_time - db.firewall_cache["last_updated"] < 300):
        return jsonify(db.firewall_cache["data"])
        
    try:
        # refresh_fw_cache()
        fw = FwService.get_connection()
        
        zone_list = sorted([z.name for z in Zone.refreshall(fw) if z.name])
        svc_list = sorted([s.name for s in PanServiceObject.refreshall(fw) if s.name])
        
        if 'any' not in zone_list: zone_list.insert(0, 'any')
        if 'application-default' not in svc_list: svc_list.insert(0, 'application-default')

        addr_objs = PanAddressObject.refreshall(fw)
        group_objs = PanAddressGroup.refreshall(fw)
        
        address_map = {a.name: a.value for a in addr_objs if a.name}
        full_addr_list = sorted([a.name for a in addr_objs if a.name] + 
                                [g.name for g in group_objs if g.name])

        response_data = {
            "status": "success", 
            "zones": zone_list, 
            "services": svc_list, 
            "addresses": full_addr_list,
            "address_map": address_map,
            "address_groups": sorted([g.name for g in group_objs if g.name]),
            "applications": ["any", "web-browsing", "ssl", "dns", "ping", "ssh", "active-directory"], 
            "tags": sorted([t.name for t in PanTag.refreshall(fw) if t.name]) if PanTag else []
        }
        
        db.firewall_cache["data"] = response_data
        db.firewall_cache["last_updated"] = current_time
        return jsonify(response_data)
    except Exception as e:
        logging.error(f"Get Params API Error: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500


# --------------------------------------------------------------------------
# V. API Routes - Commit & Job Control
# --------------------------------------------------------------------------

@ops_bp.route('/commit', methods=['POST'])
def commit_changes() -> Response:
    """Triggers a configuration commit on the firewall."""
    if not session.get('is_admin'):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403

    try:
        fw = FwService.get_connection()
        job_id = fw.commit(sync=False)
        return jsonify({"status": "success", "message": f"Commit sent! (Job ID {job_id})."})
    except Exception as e:
        if "705" in str(e) or "704" in str(e):
            return jsonify({"status": "success", "message": "Commit is already running in background."})
        return jsonify({"status": "error", "message": str(e)}), 500

@ops_bp.route('/job-status/<int:job_id>')
def get_job_status(job_id: int) -> Response:
    """Monitors job progress via Firewall XML API."""
    try:
        url = f"https://{Config.FW_IP}/api/?type=op&cmd=<show><jobs><id>{job_id}</id></jobs></show>&key={Config.API_KEY}"
        r = requests.get(url, verify=False, timeout=10)
        root = ET.fromstring(r.text)
        job = root.find(".//job")
        if job is not None:
            return jsonify({
                "status": job.findtext("status"),
                "progress": job.findtext("progress"),
                "result": job.findtext("result")
            })
        return jsonify({"status": "not_found"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


# --------------------------------------------------------------------------
# VI. Utility Tools (Match, Zone Detect & Sync)
# --------------------------------------------------------------------------

@ops_bp.route('/run-policy-match', methods=['POST'])
def run_policy_match() -> Response:
    """
    Tests traffic against the firewall. 
    Dynamic XML: Omit <from>/<to> tags if zones are empty, mimicking CLI behavior.
    """
    data = request.json or {}
    try:
        source = data.get("source_ip", "").strip()
        destination = data.get("destination_ip", "").strip()
        from_zone = data.get("from_zone", "").strip()
        to_zone = data.get("to_zone", "").strip()
        port = data.get("port", "443").strip()
        protocol = data.get("protocol", "6").strip()

        # בניית XML דינמי - השמטת תגיות אם הערך ריק או 'any'
        zone_tags = ""
        if from_zone and from_zone.lower() != 'any':
            zone_tags += f"<from>{from_zone}</from>"
        if to_zone and to_zone.lower() != 'any':
            zone_tags += f"<to>{to_zone}</to>"

        cmd = (f"<test><security-policy-match>"
               f"{zone_tags}"
               f"<source>{source}</source><destination>{destination}</destination>"
               f"<protocol>{protocol}</protocol><destination-port>{port}</destination-port>"
               f"<application>any</application>"
               f"</security-policy-match></test>")
        
        # בניית ה-URL עם vsys1 להבטחת הקשר חיפוש נכון
        url = f"https://{Config.FW_IP}/api/?type=op&cmd={cmd}&key={Config.API_KEY}&vsys=vsys1"
        
        r = requests.get(url, verify=False, timeout=15)
        xml_root = ET.fromstring(r.text)
        
        if xml_root.get('status') == 'error':
            return jsonify({"status": "error", "message": xml_root.findtext(".//msg") or "FW Error"}), 400

        entry = xml_root.find(".//entry")
        if entry is not None:
            return jsonify({
                "status": "success", "match": True, 
                "rule_name": entry.get("name"), "action": entry.findtext("action") or "allow",
                "source": source, "destination": destination
            })
            
        return jsonify({"status": "success", "match": False, "source": source, "destination": destination})
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    
@ops_bp.route('/api/detect-zone', methods=['GET'])
def detect_zone() -> Response:
    """Predicts firewall zone for an IP based on local interface subnet mapping."""
    user_input = request.args.get('ip')
    if not user_input:
        return jsonify({"status": "error", "message": "Missing input"}), 400
    try:
        from services.fw_service import FwService
        zone = FwService.detect_zone(user_input)
        return jsonify({"status": "success", "zone": zone}) if zone else jsonify({"status": "unknown"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@ops_bp.route('/api/sync/firewall', methods=['POST'])
def trigger_firewall_sync() -> Response:
    """סנכרון ידני של בסיס הנתונים מול הפיירוול (Admin only)."""
    if not session.get('is_admin'):
        return jsonify({"status": "error", "message": "Admin only"}), 403
    try:
        fw = FwService.get_connection()
        rb = Rulebase()
        fw.add(rb)
        
        # שליפת אובייקטים וקבוצות שירותים/כתובות לסנכרון מלא
        addr_objs = PanAddressObject.refreshall(fw)
        addr_groups = PanAddressGroup.refreshall(fw)
        svc_objs = PanServiceObject.refreshall(fw)
        svc_groups = PanServiceGroup.refreshall(fw)
        rules_objs = PanSecurityRule.refreshall(rb)
        
        found_apps = set()
        for r in rules_objs:
            apps = r.application
            if isinstance(apps, list): found_apps.update(apps)
            elif apps: found_apps.add(apps)
        
        apps_payload = [{"name": app, "value": "System", "is_group": False} for app in found_apps]

        fw_config = {
            'address': [obj.about() for obj in addr_objs],
            'address-group': [obj.about() for obj in addr_groups],
            'service': [obj.about() for obj in svc_objs],
            'service-group': [obj.about() for obj in svc_groups],
            'rules': [obj.about() for obj in rules_objs],
            'applications': apps_payload
        }

        sync_mgr = SyncService(fw)
        if sync_mgr.sync_all(fw_config):
            db_sql.session.add(AuditLog(user=get_username(), action="MANUAL_SYNC", resource_name="Inventory"))
            db_sql.session.commit()
            return jsonify({"status": "success", "message": "Sync completed successfully!"})
        return jsonify({"status": "error", "message": "Sync failed"}), 409
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# --------------------------------------------------------------------------
# III. Dashboard Data Aggregation APIs
# --------------------------------------------------------------------------

@ops_bp.route('/api/dashboard/operational')
def dashboard_operational():
    """Returns Operational Health metrics: connection, sync time, db size."""
    try:
        # 1. Firewall Connection Status
        fw_status = FwService.check_connection()
        
        # 2. Last Sync Time (Mocked for now or fetched from a service state if available)
        last_sync = "Just now" 
        
        # 3. Database Health (Use Config.DATA_DIR directly)
        db_path = Config.DATA_DIR / 'netops.db'
        db_size_mb = 0
        if db_path.exists():
            db_size_mb = round(db_path.stat().st_size / (1024 * 1024), 2)
            
        return jsonify({
            "fw_connection": fw_status,
            "last_sync": last_sync,
            "db_size_mb": db_size_mb,
            "status": "Healthy" if fw_status and db_size_mb < 100 else "Warning"
        })
    except Exception as e:
        logging.error(f"Dashboard Ops Error: {e}")
        return jsonify({"error": str(e)}), 500

@ops_bp.route('/api/dashboard/work-queue')
def dashboard_work_queue():
    """Returns Pending Tasks counts. Filters by user if not admin."""
    from managers.models import RuleRequest, ObjectRequest
    try:
        user = session.get('user')
        is_admin = session.get('is_admin')

        rule_query = RuleRequest.query.filter_by(status='Pending')
        obj_query = ObjectRequest.query.filter_by(status='Pending')

        if not is_admin:
            rule_query = rule_query.filter_by(requested_by=user)
            obj_query = obj_query.filter_by(requested_by=user)

        pending_rules = rule_query.count()
        pending_objects = obj_query.count()
        
        from datetime import timedelta
        week_ahead = datetime.utcnow() + timedelta(days=7)
        expiring_count = SecurityRule.query.filter(
            SecurityRule.expire_at != None,
            SecurityRule.expire_at <= week_ahead
        ).count()
        
        return jsonify({
            "pending_rules": pending_rules,
            "pending_objects": pending_objects,
            "expiring_rules": expiring_count
        })
    except Exception as e:
        logging.error(f"Dashboard Queue Error: {e}")
        return jsonify({"error": str(e)}), 500

@ops_bp.route('/api/dashboard/traffic')
def dashboard_traffic():
    """Returns aggregated traffic stats for charts."""
    from sqlalchemy import func
    try:
        # 1. Top 5 Apps
        top_apps = db_sql.session.query(
            TrafficLog.app, func.count(TrafficLog.id).label('count')
        ).group_by(TrafficLog.app).order_by(func.count(TrafficLog.id).desc()).limit(5).all()
        
        # 2. Action Ratio (Allow vs Deny)
        actions = db_sql.session.query(
            TrafficLog.action, func.count(TrafficLog.id)
        ).group_by(TrafficLog.action).all()
        
        # 3. Top Talkers (Sources)
        top_sources = db_sql.session.query(
            TrafficLog.source, func.count(TrafficLog.id)
        ).group_by(TrafficLog.source).order_by(func.count(TrafficLog.id).desc()).limit(5).all()

        return jsonify({
            "top_apps": [{"name": r[0], "count": r[1]} for r in top_apps] if top_apps else [],
            "actions": {r[0]: r[1] for r in actions} if actions else {"allow": 0, "deny": 0},
            "top_sources": [{"ip": r[0], "count": r[1]} for r in top_sources] if top_sources else []
        })
    except Exception as e:
        logging.error(f"Dashboard Traffic Error: {e}")
        return jsonify({"error": str(e)}), 500

@ops_bp.route('/api/dashboard/security')
def dashboard_security():
    """Returns Security & Audit stats. Filters by user context."""
    from sqlalchemy import func
    try:
        user = session.get('user')
        is_admin = session.get('is_admin')

        # 1. Recent Actions Ticker
        # Admin sees everything, User sees only their own
        audit_query = AuditLog.query
        if not is_admin:
            audit_query = audit_query.filter_by(user=user)
            
        recent_logs = audit_query.order_by(AuditLog.timestamp.desc()).limit(5).all()
        
        # 2. Top Admins (Activity Count)
        # Only visible to Admins
        top_admins = []
        if is_admin:
            top_admins = db_sql.session.query(
                AuditLog.user, func.count(AuditLog.id)
            ).group_by(AuditLog.user).order_by(func.count(AuditLog.id).desc()).limit(3).all()
        
        return jsonify({
            "recent_actions": [{
                "user": l.user, 
                "action": l.action, 
                "time": l.timestamp.strftime('%H:%M isostime'),
                "details": (l.details[:50] + '...') if l.details else ''
            } for l in recent_logs],
            "top_admins": [{"user": r[0], "count": r[1]} for r in top_admins]
        })
    except Exception as e:
        logging.error(f"Dashboard Security Error: {e}")
        return jsonify({"error": str(e)}), 500

@ops_bp.route('/dashboard')
def dashboard_page():
    """Renders the main dashboard page."""
    return render_template('dashboard.html')