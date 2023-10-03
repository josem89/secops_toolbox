from datetime import datetime
import re, copy, json

def get_base_timestamp(entries, mapping):
    
    events_timestamps = []
    
    for log in entries:
            log_text = log["log_text"]
            
            for timestamp in mapping["timestamps"]:
                dateformat = str(timestamp["dateformat"])
                event_time_match = re.search(timestamp["pattern"], log_text)
                if event_time_match:
                    event_timestamp = event_time_match.group(timestamp['group'])
                    
                    if timestamp["epoch"]:
                        event_timestamp = datetime.fromtimestamp(int(event_timestamp))
                        
                    elif timestamp["pattern"]:
                        event_timestamp = datetime.strptime(event_timestamp, dateformat)
                        
                    else:
                        continue
                    
                    
                    if event_timestamp:
                        events_timestamps.append(event_timestamp)
    if events_timestamps:
        return max(events_timestamps)
    else:
        return None
                    
def get_base_timestamp_udm(events, mapping):
    events_timestamps = []
    
    for event in events:
        for timestamp in mapping.get('timestamps'):
            dateformat = str(timestamp["dateformat"])
            
            
            if event.get('metadata').get(timestamp.get('name')):
                event_timestamp = event.get('metadata').get(timestamp.get('name'))
                event_timestamp = datetime.strptime(event_timestamp, dateformat)
            
                if event_timestamp:
                    events_timestamps.append(event_timestamp)

    return max(events_timestamps)

def update_events(base_events, mapping, base_timestamp, new_base_timestamp):
    
    updated_events = []
    for event in base_events:
        new_event = copy.deepcopy(event)
        
        for timestamp in mapping["timestamps"]:
            dateformat = str(timestamp["dateformat"])
            
            if event.get('metadata').get(timestamp.get('name')):
                event_time = event.get('metadata').get(timestamp.get('name'))
                
                if event_time:
                    event_time = datetime.strptime(event_time, dateformat)
                    time_delta = base_timestamp - event_time
                    new_time = new_base_timestamp - time_delta
                    new_event_timestamp = new_time.strftime(dateformat)
                    
                    new_event['metadata'][timestamp.get('name')] = new_event_timestamp
        
        updated_events.append(new_event)
    
    return updated_events
        
def update_entries(base_entries, mapping, base_timestamp, new_base_timestamp):
    
    updated_entries = []
    processed_timestamps = []   
    
    for log in base_entries:
        new_log = {}
        log_text = log["log_text"]
        
        for timestamp in mapping["timestamps"]:
            timestamps_to_update = []
            dateformat = str(timestamp["dateformat"])
            event_time_match = re.search(timestamp["pattern"], log_text)
            if event_time_match:
                event_time = event_time_match.group(timestamp['group'])
                if timestamp["epoch"]:
                    event_time = datetime.fromtimestamp(int(event_time))
                elif timestamp["pattern"]:
                    event_time = datetime.strptime(event_time, dateformat)
                        
                else:
                    continue
                    
                    
                if event_time:
                    new_time = {'is_epoch':False}
                    time_delta = base_timestamp - event_time
                    new_time = new_base_timestamp - time_delta
                    
                    
                if timestamp["epoch"]:
                    dateformat = '%s'
                    
                new_event_timestamp = new_time.strftime(dateformat)
                
                
                if event_time_match.group(timestamp['group']) in processed_timestamps:
                    continue
                
                log_text = log_text.replace(event_time_match.group(timestamp['group']), new_event_timestamp)
                processed_timestamps.append(new_event_timestamp)
        
        new_log['log_text'] = log_text
        updated_entries.append(new_log)
    
    return updated_entries