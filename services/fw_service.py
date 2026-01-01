import re
from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET

from panos.firewall import Firewall
from panos.policies import Rulebase, SecurityRule
from netaddr import IPNetwork, IPAddress, IPRange, IPSet, AddrFormatError

from config import Config
from managers.models import db_sql, AddressObject, SecurityRule as DBSecurityRule, NetworkInterface
from services.base_service import BaseService

class CustomSecurityRule(SecurityRule):
    """PAN-OS SecurityRule extended with group-tag support."""
    def __init__(self, *args, **kwargs):
        self._group_tag = kwargs.pop('group_tag', None)
        super(CustomSecurityRule, self).__init__(*args, **kwargs)

    def element_str(self) -> str:
        root = super(CustomSecurityRule, self).element_str()
        if isinstance(root, (bytes, str)):
            root = ET.fromstring(root)
        if self._group_tag:
            gt = ET.Element('group-tag')
            gt.text = self._group_tag
            root.append(gt)
        return ET.tostring(root)

class FwService(BaseService):
    """
    Service Layer for Firewall Operations.
    Handles connection, logic engines (Shadow, Zones), and execution.
    """

    @staticmethod
    def get_connection() -> Firewall:
        if not Config.FW_IP or not Config.API_KEY:
            raise ValueError("Firewall configuration missing (IP/Key)")
        return Firewall(Config.FW_IP, api_key=Config.API_KEY, verify=False, timeout=60)

    @staticmethod
    def check_connection() -> bool:
        """Verifies actual connectivity to the Firewall."""
        try:
            fw = FwService.get_connection()
            # Minimal lightweight call to verify auth and reachability
            fw.refresh_system_info() 
            return True
        except Exception:
            return False

    @staticmethod
    def sanitize_ip(val: str) -> str:
        if not val: return ""
        return re.sub(r'[^0-9\.\-\/]', '', val)

    @classmethod
    def parse_ip_to_set(cls, ip_str: str) -> IPSet:
        ip_str = cls.sanitize_ip(ip_str.strip())
        try:
            if '-' in ip_str:
                s, e = ip_str.split('-')
                return IPSet(IPRange(IPAddress(s.strip()), IPAddress(e.strip())))
            if ip_str:
                return IPSet(IPNetwork(ip_str if '/' in ip_str else f"{ip_str}/32"))
        except (AddrFormatError, ValueError):
            pass
        return IPSet()

    @classmethod
    def flatten_address(cls, obj_name: str, depth: int = 0) -> IPSet:
        """Recursively resolves objects to IPSet."""
        if depth > 10 or not obj_name: return IPSet()
        if obj_name.lower() == 'any': return IPSet(['0.0.0.0/0'])

        db_obj = AddressObject.query.filter_by(name=obj_name).first()
        if not db_obj:
            return cls.parse_ip_to_set(obj_name)

        if db_obj.is_group:
            combined = IPSet()
            for m in db_obj.members:
                combined.update(cls.flatten_address(m.name, depth + 1))
            return combined
        
        return cls.parse_ip_to_set(db_obj.value or obj_name)

    @classmethod
    def check_shadow_rule(cls, source: str, dest: str, from_zone: str, to_zone: str, service_port: str = 'any') -> Dict[str, Any]:
        """
        Advanced Policy Match Engine.
        Returns passing rule if traffic is already allowed.
        """
        src_set = cls.flatten_address(source)
        dst_set = cls.flatten_address(dest)
        
        if not src_set or not dst_set:
            return {"exists": False}

        query = DBSecurityRule.query.filter_by(disabled=False)
        if from_zone and from_zone != 'any':
            query = query.filter(DBSecurityRule.from_zone.in_([from_zone, 'any']))
        if to_zone and to_zone != 'any':
            query = query.filter(DBSecurityRule.to_zone.in_([to_zone, 'any']))

        for rule in query.all():
            # Source Check
            # If no sources linked, likely 'any' (failed to link) or explicit 'any'. Treat as 0.0.0.0/0
            if not rule.sources:
                r_src = IPSet(['0.0.0.0/0'])
            else:
                r_src = IPSet()
                for s in rule.sources: r_src.update(cls.flatten_address(s.name))
            
            if not src_set.issubset(r_src): continue

            # Dest Check
            if not rule.destinations:
                r_dst = IPSet(['0.0.0.0/0'])
            else:
                r_dst = IPSet()
                for d in rule.destinations: r_dst.update(cls.flatten_address(d.name))
            
            if not dst_set.issubset(r_dst): continue

            # Service Check (Technical Match)
            # If request is specific port, rule must include it or be 'any'/'application-default'
            
            # If no services linked, treat as ANY/Application-Default
            if not rule.services:
                 return {"exists": True, "rule": rule.name, "action": rule.action}

            # Simplified Logic: Check if rule has 'any', 'application-default' or the specific service object
            
            # TODO: Add deep port resolution (e.g. 'web-browsing' -> 80). 
            # For now, string match against rule services is a reasonable start given "application-default" usage.
            
            rule_services = [s.name.lower() for s in rule.services]
            if 'any' in rule_services or 'application-default' in rule_services:
                return {"exists": True, "rule": rule.name, "action": rule.action}
            
            # If user asks for 'tcp-80' and rule has 'tcp-80', match.
            # If user asks for '80', checking direct match might fail if object is named 'http'.
            # Assuming user inputs Object Name or Port that lines up with DB conventions for now.
            
            input_svc = service_port.lower()
            if input_svc in rule_services:
                 return {"exists": True, "rule": rule.name, "action": rule.action}

            # If we reached here, IP matched but Service didn't. Continue to next rule.
            continue

        return {"exists": False}

    @classmethod
    def detect_zone(cls, ip_input: str) -> Optional[str]:
        """Maps IP to Zone using DB Topology."""
        target = cls.flatten_address(ip_input)
        if not target: return None

        interfaces = NetworkInterface.query.all()
        detected = set()

        for cidr in target.iter_cidrs():
            for iface in interfaces:
                if not iface.subnet: continue
                if cidr in IPNetwork(iface.subnet) or IPNetwork(iface.subnet) in cidr:
                    detected.add(iface.zone_name)
                    break 
        
        return list(detected)[0] if detected else None
