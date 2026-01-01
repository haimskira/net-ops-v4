from flask import Blueprint, request, jsonify, session
import os
from dotenv import load_dotenv, set_key

admin_bp = Blueprint('admin', __name__)

ENV_PATH = '.env'

def is_admin_user():
    return session.get('is_admin')

@admin_bp.route('/get-env-config')
def get_env_config():
    if not is_admin_user(): return jsonify({"message": "Unauthorized"}), 403
    
    # Read fresh
    # We only return specific keys for security/relevance
    keys = ['FW_IP', 'PA_API_KEY', 'LDAP_SERVER', 'LDAP_DOMAIN', 'LDAP_BASE_DN', 'LDAP_ADMIN_GROUP', 'LDAP_USER_GROUP']
    data = {}
    
    # Reload environment to ensure we have latest from file if it changed externally
    # Actually, os.environ is process-bound. To read file explicitly:
    from dotenv import dotenv_values
    config = dotenv_values(ENV_PATH) # returns dict from .env file
    
    for k in keys:
        data[k] = config.get(k, '')
        
    return jsonify(data)

@admin_bp.route('/update-env-config', methods=['POST'])
def update_env_config():
    if not is_admin_user(): return jsonify({"message": "Unauthorized"}), 403
    
    data = request.json
    try:
        # Update .env file
        # We loop through allowed keys and set them
        keys = ['FW_IP', 'PA_API_KEY', 'LDAP_SERVER', 'LDAP_DOMAIN', 'LDAP_BASE_DN', 'LDAP_ADMIN_GROUP', 'LDAP_USER_GROUP']
        
        for k in keys:
            if k in data:
                # set_key works on the file
                set_key(ENV_PATH, k, data[k])
                
        # Optional: Reload in current process (doesn't always affect loaded modules mostly)
        # But Config object might need refresh?
        # Ideally, we ask user to restart, but we can try to patch os.environ
        for k, v in data.items():
            if k in keys:
                os.environ[k] = v
                
        return jsonify({"status": "success", "message": "Configuration saved. Please restart the container/application for full effect."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
