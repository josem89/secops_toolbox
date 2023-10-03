from DataModels import UnstructuredLogs, UdmEvents, DetectionRule, ChronicleRule
from constants import LOG_TYPE_MAPPING, ENTITIES_MAPPING
import base64, json

def parse_events(raw_data, new_base_time):
    
    log_type = raw_data.get('file_name').replace('.log','')
    raw_content = parse_file_content(raw_data.get('content'))
    
    if LOG_TYPE_MAPPING.get(log_type).get('api') == "unstructuredlogentries":
        return UnstructuredLogs(raw_content, log_type, LOG_TYPE_MAPPING.get(log_type), new_base_time)
    
    elif LOG_TYPE_MAPPING.get(log_type).get('api') == "udmevents":
        return UdmEvents(raw_content, LOG_TYPE_MAPPING.get(log_type), new_base_time)
    
        

def parse_entities(raw_data, new_base_time,):
    
    log_type = raw_data.get('file_name').replace('.log','')
    raw_content = parse_file_content(raw_data.get('content'))
    return UnstructuredLogs(raw_content, log_type, ENTITIES_MAPPING.get(log_type), new_base_time)

def parse_rules(raw_data):
    
    rule_name = raw_data.get('file_name')
    raw_content = parse_file_content(raw_data.get('content'))
    return DetectionRule(raw_content, rule_name)
    

def parse_file_content(encoded_content):

    base64_bytes = encoded_content.encode('UTF-8')
    event_content_bytes = base64.b64decode(base64_bytes)
    return event_content_bytes.decode('UTF-8')

def parse_chronicle_rules(rules):
    return [ChronicleRule(rule) for rule in rules ]