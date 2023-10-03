from utils import get_base_timestamp, get_base_timestamp_udm, update_entries, update_events
import json

class UnstructuredLogs(object):
    def __init__(self, content, log_type, event_mapping, new_base_time):
        self.base_entries = [{'log_text': log} for log in content.splitlines()]
        self.mapping = event_mapping
        self.base_timestamp = get_base_timestamp(self.base_entries, self.mapping)
        self.customer_id = None
        self.log_type = log_type
        self.api = "unstructured"
        self.entries = update_entries(self.base_entries, self.mapping, self.base_timestamp, new_base_time)
    
class UdmEvents(object):
    def __init__(self, content, event_mapping, new_base_time):
        self.base_events = [json.loads(event) for event in content.splitlines()]
        self.mapping = event_mapping
        self.base_timestamp = get_base_timestamp_udm(self.base_events, self.mapping)
        self.api = "udmevents"
        self.events = update_events(self.base_events, self.mapping, self.base_timestamp, new_base_time)
    
class DetectionRule(object):
    def __init__(self, content, rule_name):
        self.name = rule_name
        self.content = content
        self.exists = False
        self.is_synced = False
        self.id = None
        self.is_live = False
        self.is_alerting = False
        
class ChronicleRule(object):
    def __init__(self, rule):
        self.name = rule.get('ruleName')
        self.content = rule.get('ruleText')
        self.id = rule.get('ruleId')
        self.is_live = False if not rule.get('liveRuleEnabled') else True
        self.is_alerting = False if not rule.get('alertingEnabled') else True