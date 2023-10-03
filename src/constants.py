

#CHRONICLE_ENDPOINTS=

CHRONICLE_API_URL = "https://malachiteingestion-pa.googleapis.com"

GIT_ENDPOINTS = {
    "get_project_tree": "/api/v4/projects/{project_id}/repository/tree",
    "get_file": "/api/v4/projects/{project_id}/repository/files/{file_path}",
    "create_rule": "/v2/detect/rules",
    "create_rule_version":"v2/detect/rules/{ruleId}:createVersion"
}


DEFAULT_PROJECT = "49166120"
DEFAULT_TOKEN = "glpat-8FWKwhVx1PeU39BkjVGW"
USE_CASES_PATH = "SIEM-CONTENT/usecases"
RULES_PATH = "SIEM-CONTENT/rules"

ENTITIES_MAPPING = {
  "GCP_BIGQUERY_CONTEXT": {
    "api": "unstructuredlogentries",
    "btspattern": "(\"creationTime\":\\s*\"?)(\\d{10})",
    "btsgroup": 2,
    "btsformat": "%s",
    "btsepoch": True,
    "timestamps": [
      {
        "name": "gcp_creationTime",
        "dateformat": "%s",
        "pattern": "(\"creationTime\":\\s*\"?)(\\d{10})",
        "epoch": True,
        "group": 2
      },
      {
        "name": "gcp_expirationTime",
        "dateformat": "%s",
        "pattern": "(\"expirationTime\":\\s*\"?)(\\d{10})",
        "epoch": True,
        "group": 2
      }
    ]
  },
  "GCP_COMPUTE_CONTEXT": {
    "api": "unstructuredlogentries",
    "btspattern": "(creationTimestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "gcp_creationTimestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(creationTimestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})",
        "epoch": False,
        "group": 2
      },
      {
        "name": "gcp_lastStartTimestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(lastStartTimestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "GCP_DLP_CONTEXT": {
    "api": "unstructuredlogentries",
    "btspattern": "(timestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*|Z\")",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "gcp_dlp_entity_timestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(timestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*|Z\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "gcp_dlp_entity_createTime",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(createTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*|Z\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "gcp_dlp_entity_lastModifiedTime",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(lastModifiedTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*|Z\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "gcp_dlp_entity_expirationTime",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(expirationTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*|Z\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "gcp_dlp_entity_profileLastGenerated",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(profileLastGenerated\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*|Z\")",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "GCP_IAM_ANALYSIS": {
    "api": "entities",
    "btspattern": "(\"seconds\":\\s*\"?)(\\d+)(\\s*\")",
    "btsgroup": 2,
    "btsformat": "%s",
    "btsepoch": True,
    "timestamps": [
      {
        "name": "gcp_iam_entity_timestamp",
        "dateformat": "%s",
        "pattern": "(\"seconds\":\\s*\"?)(\\d+)(\\s*\")",
        "epoch": True,
        "group": 2
      }
    ]
  },
  "GCP_IAM_CONTEXT": {
    "api": "unstructuredlogentries",
    "btspattern": "(timestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "gcp_Timestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(timestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "OKTA_USER_CONTEXT": {
    "api": "unstructuredlogentries",
    "btspattern": "(lastLogin\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*|Z\")",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "lastLogin",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(lastLogin\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*|Z\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "lastUpdated",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(lastUpdated\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*|Z\")",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "WORKSPACE_USERS": {
    "api": "unstructuredlogentries",
    "btspattern": "(lastLoginTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*|Z\")",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "gcp_lastLoginTime",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(lastLoginTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*|Z\")",
        "epoch": False,
        "group": 2
      }
    ]
  }
}


LOG_TYPE_MAPPING = {
  "AUDITD": {
    "api": "unstructuredlogentries",
    "btspattern": "(\\s*?)(\\d{10})(.\\d+\\s*)",
    "btsgroup": 2,
    "btsformat": "%s",
    "btsepoch": True,
    "timestamps": [
      {
        "name": "syslog_timestamp",
        "dateformat": "%b %d %H:%M:%S",
        "pattern": "(<\\d+>)([a-zA-Z]{3}\\s+\\d+\\s+\\d\\d:\\d\\d:\\d\\d)",
        "epoch": False,
        "group": 2
      },
      {
        "name": "event_time",
        "dateformat": "%s",
        "pattern": "(\\s*?)(\\d{10})(.\\d+\\s*)",
        "epoch": True,
        "group": 2
      }
    ]
  },
  "AWS_CLOUDTRAIL": {
    "api": "unstructuredlogentries",
    "btspattern": "(eventTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z)(\\s*\")",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%SZ",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "event_time",
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "pattern": "(eventTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z)(\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "creation_date",
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "pattern": "(creationDate\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z)(\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "create_date",
        "dateformat": "%b %d, %Y %H:%M:%S %p",
        "pattern": "(createDate\"\\s*:\\s*\"?)([a-zA-Z]{3}\\s\\d+,\\s\\d{4}\\s+\\d+:\\d+:\\d+\\s[AP]M)(\\s*\")",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "AZURE_AD": {
    "api": "unstructuredlogentries",
    "btspattern": "(createdDateTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z)(\\s*\")",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%SZ",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "createdDateTime",
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "pattern": "(createdDateTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z)(\\s*\")",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "BRO_JSON": {
    "api": "unstructuredlogentries",
    "btspattern": "(\"ts\":\\s*?)(\\d{10})(.\\d+\\s*)",
    "btsgroup": 2,
    "btsformat": None,
    "btsepoch": True,
    "timestamps": [
      {
        "name": "zeek_ts",
        "dateformat": "%s",
        "pattern": "(\"ts\":\\s*?)(\\d{10})(.\\d+\\s*)",
        "epoch": True,
        "group": 2
      }
    ]
  },
  "CB_EDR": {
    "api": "unstructuredlogentries",
    "btspattern": "(\"timestamp\":\\s*)(\\d{10})",
    "btsgroup": 2,
    "btsformat": None,
    "btsepoch": True,
    "timestamps": [
      {
        "name": "cb_edr_timestamp",
        "dateformat": "%s",
        "pattern": "(\"timestamp\":\\s*)(\\d{10})",
        "epoch": True,
        "group": 2
      }
    ]
  },
  "CHROME_MANAGEMENT": {
    "api": "unstructuredlogentries",
    "btspattern": "(\"time\":\\s+\")(\\d{10})(.\\d+\\s*\")?",
    "btsgroup": 2,
    "btsformat": None,
    "btsepoch": True,
    "timestamps": [
      {
        "name": "chrome_timestamp",
        "dateformat": "%s",
        "pattern": "(\"time\":\\s+\")(\\d{10})(.\\d+\\s*\")?",
        "epoch": True,
        "group": 2
      }
    ]
  },
  "CS_EDR": {
    "api": "unstructuredlogentries",
    "btspattern": "(\"timestamp\":\\s*\"?)(\\d{10})",
    "btsgroup": 2,
    "btsformat": None,
    "btsepoch": True,
    "timestamps": [
      {
        "name": "cs_edr_timestamp",
        "dateformat": "%s",
        "pattern": "(\"timestamp\":\\s*\"?)(\\d{10})",
        "epoch": True,
        "group": 2
      },
      {
        "name": "ContextTimeStamp",
        "dateformat": "%s",
        "pattern": "(\"ContextTimeStamp\":\\s*\"?)(\\d{10})",
        "epoch": True,
        "group": 2
      },
      {
        "name": "AgentLocalTime",
        "dateformat": "%s",
        "pattern": "(\"AgentLocalTime\":\\s*\"?)(\\d{10})",
        "epoch": True,
        "group": 2
      }
    ]
  },
  "FIREEYE_HX": {
    "api": "unstructuredlogentries",
    "btspattern": "(\"event_at\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "fireeye_timestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "GCP_CLOUDAUDIT": {
    "api": "unstructuredlogentries",
    "btspattern": "(timestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "gcp_time",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(time\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "gcp_timestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(timestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "receiveTimestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(receiveTimestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "GCP_CLOUD_NAT": {
    "api": "unstructuredlogentries",
    "btspattern": "(timestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "gcp_timestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(timestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "receiveTimestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(receiveTimestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "GCP_DNS": {
    "api": "unstructuredlogentries",
    "btspattern": "(timestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "gcp_timestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(timestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "receiveTimestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(receiveTimestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "GCP_FIREWALL": {
    "api": "unstructuredlogentries",
    "btspattern": "(timestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*|Z\")",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "gcp_timestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(timestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*|Z\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "gcp_receiveTimestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(receiveTimestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*|Z\")",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "GCP_IDS": {
    "api": "unstructuredlogentries",
    "btspattern": "(timestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(Z\")",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "gcp_timestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(timestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(Z\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "receiveTimestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(receiveTimestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "GCP_LOADBALANCING": {
    "api": "unstructuredlogentries",
    "btspattern": "(timestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "gcp_timestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(timestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "receiveTimestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(receiveTimestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "GCP_SECURITYCENTER_THREAT": {
    "api": "unstructuredlogentries",
    "btspattern": "(\"eventTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "gcp_eventTime",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(\"eventTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "gcp_createTime",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(\"createTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "timestamp",
        "dateformat": "%s",
        "pattern": "(\"seconds\":\\s*\")(\\d{10})",
        "epoch": True,
        "group": 2
      }
    ]
  },
  "GCP_SECURITYCENTER_MISCONFIGURATION": {
    "api": "unstructuredlogentries",
    "btspattern": "(\"eventTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "gcp_eventTime",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(\"eventTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "gcp_createTime",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(\"createTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "timestamp",
        "dateformat": "%s",
        "pattern": "(\"seconds\":\\s*\")(\\d{10})",
        "epoch": True,
        "group": 2
      }
    ]
  },
  "GCP_VPC_FLOW": {
    "api": "unstructuredlogentries",
    "btspattern": "(timestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "gcp_timestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(timestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "receiveTimestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(receiveTimestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "gcp_end_time",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(end_time\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "gcp_start_time",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(start_time\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "GMAIL_LOGS": {
    "api": "unstructuredlogentries",
    "btspattern": "(\"timestamp_usec\":\\s+\")(\\d{10})(\\d{6}\")",
    "btsgroup": 2,
    "btsformat": None,
    "btsepoch": True,
    "timestamps": [
      {
        "name": "timestamp",
        "dateformat": "%s",
        "pattern": "(\"timestamp_usec\":\\s+\")(\\d{10})(\\d{6})",
        "epoch": True,
        "group": 2
      }
    ]
  },
  "GUARDDUTY": {
    "api": "unstructuredlogentries",
    "btspattern": "(\"updatedAt\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "createdAt",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(\"createdAt\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "updatedAt",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(\"updatedAt\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "eventFirstSeen",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(\"eventFirstSeen\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "eventLastSeen",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(\"eventLastSeen\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "INFOBLOX_DHCP": {
    "api": "unstructuredlogentries",
    "btspattern": "(<\\d+>.*)([a-zA-Z]{3}\\s+\\d+\\s+\\d\\d:\\d\\d:\\d\\d)",
    "btsgroup": 2,
    "btsformat": "%b %d %H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "syslog_timestamp",
        "dateformat": "%b %d %H:%M:%S",
        "pattern": "(<\\d+>.*)([a-zA-Z]{3}\\s+\\d+\\s+\\d\\d:\\d\\d:\\d\\d)",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "EXTRAHOP_DNS": {
    "api": "unstructuredlogentries",
    "btspattern": "(<\\d+>.*)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z)",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "syslog_timestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(<\\d+>.*)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z)",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "LIMACHARLIE_EDR": {
    "api": "unstructuredlogentries",
    "btspattern": "(\"TIMESTAMP\":)(\\d{10})(\\d{3})",
    "btsgroup": 2,
    "btsformat": None,
    "btsepoch": True,
    "timestamps": [
      {
        "name": "TIMESTAMP",
        "dateformat": "%s",
        "pattern": "(\"TIMESTAMP\":)(\\d{10})(\\d{3})",
        "epoch": True,
        "group": 2
      },
      {
        "name": "event_time",
        "dateformat": "%s",
        "pattern": "(\"event_time\":)(\\d{10})(\\d{3})",
        "epoch": True,
        "group": 2
      }
    ]
  },
  "OKTA": {
    "api": "unstructuredlogentries",
    "btspattern": "(\"published\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "published",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(\"published\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "authMethodFirstVerificationTime",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(\"authMethodFirstVerificationTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "authMethodSecondVerificationTime",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(\"authMethodSecondVerificationTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "suspiciousActivityTimestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(\"suspiciousActivityTimestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "SURICATA_EVE": {
    "api": "unstructuredlogentries",
    "btspattern": "(\"timestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "timestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(\"timestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})",
        "epoch": False,
        "group": 2
      },
      {
        "name": "start",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(\"start\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "TANIUM_TH": {
    "api": "unstructuredlogentries",
    "btspattern": "(\"eventTimestamp\":\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+)",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "eventTimestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(\"eventTimestamp\":\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+)",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "UDM": {
    "api": "udmevents",
    "btspattern": "(\"event_timestamp\":\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z)(\\s*\")",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%SZ",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "event_timestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%SZ",
        "pattern": "(\"event_timestamp\":\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z)(\\s*\")",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "WINDOWS_DHCP": {
    "api": "unstructuredlogentries",
    "btspattern": "(,)(\\d\\d\\/\\d\\d\\/\\d\\d,\\d\\d:\\d\\d:\\d\\d)(,)",
    "btsgroup": 2,
    "btsformat": "%m/%d/%y,%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "dhcp_timestamp",
        "dateformat": "%m/%d/%y,%H:%M:%S",
        "pattern": "(,)(\\d\\d\\/\\d\\d\\/\\d\\d,\\d\\d:\\d\\d:\\d\\d)(,)",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "WINDOWS_SYSMON": {
    "api": "unstructuredlogentries",
    "btspattern": "(UtcTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d+)(\\s*\")",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%d %H:%M:%S.%f",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "syslog_timestamp",
        "dateformat": "%b %d %H:%M:%S",
        "pattern": "(<\\d+>)([a-zA-Z]{3}\\s+\\d+\\s+\\d\\d:\\d\\d:\\d\\d)",
        "epoch": False,
        "group": 2
      },
      {
        "name": "EventTime",
        "dateformat": "%s",
        "pattern": "(\"EventTime\":)(\\d+)(,)",
        "epoch": True,
        "group": 2
      },
      {
        "name": "EventTimeUTC",
        "dateformat": "%Y-%m-%d %H:%M:%S",
        "pattern": "(\"EventTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})(\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "EventReceivedTime",
        "dateformat": "%s",
        "pattern": "(\"EventReceivedTime\":)(\\d+)(,)",
        "epoch": True,
        "group": 2
      },
      {
        "name": "EventReceivedTimeUTC",
        "dateformat": "%Y-%m-%d %H:%M:%S",
        "pattern": "(\"EventReceivedTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})(\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "CreationUtcTime",
        "dateformat": "%Y-%m-%d %H:%M:%S.%f",
        "pattern": "(CreationUtcTime\\s*:\\s*)(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d+)",
        "epoch": False,
        "group": 2
      },
      {
        "name": "CreationUtcTimeQuotes",
        "dateformat": "%Y-%m-%d %H:%M:%S.%f",
        "pattern": "(CreationUtcTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d+)(\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "UtcTime",
        "dateformat": "%Y-%m-%d %H:%M:%S.%f",
        "pattern": "(UtcTime\\s*:\\s*)(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d+)",
        "epoch": False,
        "group": 2
      },
      {
        "name": "UtcTimeQuotes",
        "dateformat": "%Y-%m-%d %H:%M:%S.%f",
        "pattern": "(UtcTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}\\.\\d+)(\\s*\")",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "POWERSHELL": {
    "api": "unstructuredlogentries",
    "btspattern": "\"EventTime\":(\\d+)",
    "btsgroup": 1,
    "btsformat": None,
    "btsepoch": True,
    "timestamps": [
      {
        "name": "syslog_timestamp",
        "dateformat": "%b %d %H:%M:%S",
        "pattern": "(<\\d+>)([a-zA-Z]{3}\\s+\\d+\\s+\\d\\d:\\d\\d:\\d\\d)",
        "epoch": False,
        "group": 2
      },
      {
        "name": "EventTime",
        "dateformat": "%s",
        "pattern": "(\"EventTime\":)(\\d+)(,)",
        "epoch": True,
        "group": 2
      },
      {
        "name": "EventReceivedTime",
        "dateformat": "%s",
        "pattern": "(\"EventReceivedTime\":)(\\d+)(,)",
        "epoch": True,
        "group": 2
      }
    ]
  },
  "SENTINEL_EDR": {
    "api": "unstructuredlogentries",
    "btspattern": "(\"@timestamp\":)(\\d{10})",
    "btsgroup": 2,
    "btsformat": None,
    "btsepoch": True,
    "timestamps": [
      {
        "name": "timestamp",
        "dateformat": "%s",
        "pattern": "(\"@timestamp\":)(\\d{10})",
        "epoch": True,
        "group": 2
      },
      {
        "name": "millisecondsSinceEpoch",
        "dateformat": "%s",
        "pattern": "(\"millisecondsSinceEpoch\"\\s*:\\s*\"?)(\\d{10})",
        "epoch": True,
        "group": 2
      }
    ]
  },
  "SEP": {
    "api": "unstructuredlogentries",
    "btspattern": "(<\\d+>)([a-zA-Z]{3}\\s+\\d+\\s+\\d\\d:\\d\\d:\\d\\d)",
    "btsgroup": 2,
    "btsformat": "%b %d %H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "time",
        "dateformat": "%Y-%m-%d %H:%M:%S",
        "pattern": "(Event time: )(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})",
        "epoch": False,
        "group": 2
      },
      {
        "name": "syslog_timestamp",
        "dateformat": "%b %d %H:%M:%S",
        "pattern": "(<\\d+>)([a-zA-Z]{3}\\s+\\d+\\s+\\d\\d:\\d\\d:\\d\\d)",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "SQUID_WEBPROXY": {
    "api": "unstructuredlogentries",
    "btspattern": "(\\d{10})(.\\d{3})",
    "btsgroup": 1,
    "btsformat": None,
    "btsepoch": True,
    "timestamps": [
      {
        "name": "syslog_timestamp",
        "dateformat": "%s",
        "pattern": "(\\d{10})(.\\d{3})",
        "epoch": True,
        "group": 1
      }
    ]
  },
  "WINEVTLOG": {
    "api": "unstructuredlogentries",
    "btspattern": "\"EventTime\":(\\d+)",
    "btsgroup": 1,
    "btsformat": None,
    "btsepoch": True,
    "timestamps": [
      {
        "name": "syslog_timestamp",
        "dateformat": "%b %d %H:%M:%S",
        "pattern": "(<\\d+>)([a-zA-Z]{3}\\s+\\d+\\s+\\d\\d:\\d\\d:\\d\\d)",
        "epoch": False,
        "group": 2
      },
      {
        "name": "EventTime",
        "dateformat": "%s",
        "pattern": "(\"EventTime\":)(\\d+)(,)",
        "epoch": True,
        "group": 2
      },
      {
        "name": "EventTimeUTC",
        "dateformat": "%Y-%m-%d %H:%M:%S",
        "pattern": "(\"EventTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})(\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "EventReceivedTime",
        "dateformat": "%s",
        "pattern": "(\"EventReceivedTime\":)(\\d+)(,)",
        "epoch": True,
        "group": 2
      },
      {
        "name": "EventReceivedTimeUTC",
        "dateformat": "%Y-%m-%d %H:%M:%S",
        "pattern": "(\"EventReceivedTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})(\\s*\")",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "WINDOWS_DEFENDER_ATP": {
    "api": "unstructuredlogentries",
    "btspattern": "(\"time\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "time",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(\"time\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "Timestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(\"Timestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "ProcessParentCreationTime",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(ProcessParentCreationTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "ProcessCreationTime",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(ProcessCreationTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "WINDOWS_DEFENDER_AV": {
    "api": "unstructuredlogentries",
    "btspattern": "\"EventTime\":(\\d+)",
    "btsgroup": 1,
    "btsformat": None,
    "btsepoch": True,
    "timestamps": [
      {
        "name": "syslog_timestamp",
        "dateformat": "%b %d %H:%M:%S",
        "pattern": "(<\\d+>)([a-zA-Z]{3}\\s+\\d+\\s+\\d\\d:\\d\\d:\\d\\d)",
        "epoch": False,
        "group": 2
      },
      {
        "name": "EventTime",
        "dateformat": "%s",
        "pattern": "(\"EventTime\":)(\\d+)(,)",
        "epoch": True,
        "group": 2
      },
      {
        "name": "EventReceivedTime",
        "dateformat": "%s",
        "pattern": "(\"EventReceivedTime\":)(\\d+)(,)",
        "epoch": True,
        "group": 2
      },
      {
        "name": "DynamicSecurityIntelligenceCompilationTimestamp",
        "dateformat": "%m/%d/%Y %I:%M:%S %p",
        "pattern": "(Dynamic security intelligence Compilation Timestamp: )(\\d+/\\d+/\\d{4} \\d+:\\d+:\\d+ [AP]M)",
        "epoch": False,
        "group": 2
      },
      {
        "name": "DynamicSecurityIntelligenceCompilationTimestampQuotes",
        "dateformat": "%m/%d/%Y %I:%M:%S %p",
        "pattern": "(\"Dynamic security intelligence Compilation Timestamp\"\\s*:\\s*\"?)(\\d+/\\d+/\\d{4} \\d+:\\d+:\\d+ [AP]M)(\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "LastQuickScanStartTime",
        "dateformat": "%m/%d/%Y %I:%M:%S %p",
        "pattern": "(Last quick scan start time: )(\\d+/\\d+/\\d{4} \\d+:\\d+:\\d+ [AP]M)",
        "epoch": False,
        "group": 2
      },
      {
        "name": "LastQuickScanStartTimeQuotes",
        "dateformat": "%m/%d/%Y %I:%M:%S %p",
        "pattern": "(Last quick scan start time\"\\s*:\\s*\"?)(\\d+/\\d+/\\d{4} \\d+:\\d+:\\d+ [AP]M)(\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "LastQuickScanEndTime",
        "dateformat": "%m/%d/%Y %I:%M:%S %p",
        "pattern": "(Last quick scan end time: )(\\d+/\\d+/\\d{4} \\d+:\\d+:\\d+ [AP]M)",
        "epoch": False,
        "group": 2
      },
      {
        "name": "LastQuickScanEndTimeQuotes",
        "dateformat": "%m/%d/%Y %I:%M:%S %p",
        "pattern": "(Last quick scan end time\"\\s*:\\s*\"?)(\\d+/\\d+/\\d{4} \\d+:\\d+:\\d+ [AP]M)(\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "Antivirus_security_intelligence_creation_time",
        "dateformat": "%m/%d/%Y %I:%M:%S %p",
        "pattern": "(Antivirus security intelligence creation time: )(\\d+/\\d+/\\d{4} \\d+:\\d+:\\d+ [AP]M)",
        "epoch": False,
        "group": 2
      },
      {
        "name": "AV_security_intelligence_creation_time_quotes",
        "dateformat": "%m/%d/%Y %I:%M:%S %p",
        "pattern": "(AV security intelligence creation time\"\\s*:\\s*\"?)(\\d+/\\d+/\\d{4} \\d+:\\d+:\\d+ [AP]M)(\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "AS_security_intelligence_creation_time_quotes",
        "dateformat": "%m/%d/%Y %I:%M:%S %p",
        "pattern": "(AS security intelligence creation time\"\\s*:\\s*\"?)(\\d+/\\d+/\\d{4} \\d+:\\d+:\\d+ [AP]M)(\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "Antispyware_security_intelligence_creation_time",
        "dateformat": "%m/%d/%Y %I:%M:%S %p",
        "pattern": "(Antispyware security intelligence creation time: )(\\d+/\\d+/\\d{4} \\d+:\\d+:\\d+ [AP]M)",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "MICROSOFT_DEFENDER_ENDPOINT": {
    "api": "unstructuredlogentries",
    "btspattern": "(\"time\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "time",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(\"time\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "Timestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(\"Timestamp\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "ProcessParentCreationTime",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(ProcessParentCreationTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      },
      {
        "name": "ProcessCreationTime",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(ProcessCreationTime\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "NIX_SYSTEM": {
    "api": "unstructuredlogentries",
    "btspattern": "(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})",
    "btsgroup": 1,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "syslog_timestamp",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})",
        "epoch": False,
        "group": 1
      }
    ]
  },
  "WINDOWS_AD": {
    "api": "unstructuredlogentries",
    "btspattern": "(\"Created\"\\s*:\\s*\"\\\\\\\\\\/Date\\(-?)(\\d{10})(\\d{3})",
    "btsgroup": 2,
    "btsformat": None,
    "btsepoch": True,
    "timestamps": [
      {
        "name": "Date",
        "dateformat": "%s",
        "pattern": "(\"\\\\\\\\\\/Date\\(-?)(\\d{10})(\\d{3})",
        "epoch": True,
        "group": 2
      }
    ]
  },
  "WORKSPACE_ACTIVITY": {
    "api": "unstructuredlogentries",
    "btspattern": "(\"time\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
    "btsgroup": 2,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "time",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(\"time\"\\s*:\\s*\"?)(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})(.\\d+Z\\s*\")",
        "epoch": False,
        "group": 2
      }
    ]
  },
  "WORKSPACE_ALERTS": {
    "api": "unstructuredlogentries",
    "btspattern": "(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})",
    "btsgroup": 1,
    "btsformat": "%Y-%m-%dT%H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "time",
        "dateformat": "%Y-%m-%dT%H:%M:%S",
        "pattern": "(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})",
        "epoch": False,
        "group": 1
      }
    ]
  },
  "ZSCALER_WEBPROXY": {
    "api": "unstructuredlogentries",
    "btspattern": "(\\d{4}-\\d{2}-\\d{2}\\s\\d{2}:\\d{2}:\\d{2})",
    "btsgroup": 1,
    "btsformat": "%Y-%m-%d %H:%M:%S",
    "btsepoch": False,
    "timestamps": [
      {
        "name": "zscaler_event_timestamp",
        "dateformat": "%Y-%m-%d %H:%M:%S",
        "pattern": "(\\d{4}-\\d{2}-\\d{2}\\s\\d{2}:\\d{2}:\\d{2})",
        "epoch": False,
        "group": 1
      }
    ]
  }
}