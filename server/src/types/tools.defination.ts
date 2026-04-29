[
  {
    "name": "get_investigation_details",
    "description": "Fetch full investigation details including alerts, entities, and timeline.",
    "input_schema": {
      "type": "object",
      "properties": {
        "investigation_id": { "type": "string" }
      },
      "required": ["investigation_id"]
    }
  },
  {
    "name": "get_alert_context",
    "description": "Fetch detailed alert metadata such as severity, detection rule, and associated entities.",
    "input_schema": {
      "type": "object",
      "properties": {
        "alert_id": { "type": "string" }
      },
      "required": ["alert_id"]
    }
  },
  {
    "name": "get_user_activity",
    "description": "Fetch user activity logs including logins, access events, and suspicious behavior.",
    "input_schema": {
      "type": "object",
      "properties": {
        "username": { "type": "string" },
        "time_range": {
          "type": "string",
          "enum": ["24h", "7d", "30d"]
        }
      },
      "required": ["username"]
    },
    "metadata": { "cost": "medium", "latency": "high" }
  },
  {
    "name": "get_asset_activity",
    "description": "Fetch activity logs for an asset such as processes, network events, and alerts.",
    "input_schema": {
      "type": "object",
      "properties": {
        "asset_id": { "type": "string" },
        "time_range": {
          "type": "string",
          "enum": ["24h", "7d", "30d"]
        }
      },
      "required": ["asset_id"]
    },
    "metadata": { "cost": "medium", "latency": "high" }
  },
  {
    "name": "get_ip_activity",
    "description": "Fetch activity related to an IP including connections and login attempts.",
    "input_schema": {
      "type": "object",
      "properties": {
        "ip": { "type": "string" },
        "time_range": {
          "type": "string",
          "enum": ["24h", "7d", "30d"]
        }
      },
      "required": ["ip"]
    }
  },
  {
    "name": "get_process_activity",
    "description": "Fetch process execution details including parent-child relationships.",
    "input_schema": {
      "type": "object",
      "properties": {
        "process_name": { "type": "string" },
        "asset_id": { "type": "string" }
      },
      "required": ["process_name"]
    }
  },
  {
    "name": "geoip_lookup",
    "description": "Get geographic and ISP details for an IP.",
    "input_schema": {
      "type": "object",
      "properties": {
        "ip": { "type": "string" }
      },
      "required": ["ip"]
    },
    "metadata": { "cost": "low", "latency": "low" }
  },
  {
    "name": "threat_intel_lookup",
    "description": "Check if indicator (IP/domain/hash) is malicious.",
    "input_schema": {
      "type": "object",
      "properties": {
        "indicator": { "type": "string" },
        "type": {
          "type": "string",
          "enum": ["ip", "domain", "hash"]
        }
      },
      "required": ["indicator", "type"]
    },
    "metadata": { "cost": "low", "latency": "medium" }
  },
  {
    "name": "whois_lookup",
    "description": "Fetch WHOIS registration details.",
    "input_schema": {
      "type": "object",
      "properties": {
        "target": { "type": "string" }
      },
      "required": ["target"]
    }
  },
  {
    "name": "correlate_entities",
    "description": "Correlate user, IP, and asset across logs to find relationships.",
    "input_schema": {
      "type": "object",
      "properties": {
        "entity": { "type": "string" }
      },
      "required": ["entity"]
    }
  },
  {
    "name": "get_login_anomalies",
    "description": "Detect unusual login behavior such as impossible travel or new devices.",
    "input_schema": {
      "type": "object",
      "properties": {
        "username": { "type": "string" }
      },
      "required": ["username"]
    }
  },
  {
    "name": "get_asset_risk_score",
    "description": "Fetch risk score or past incident history for an asset.",
    "input_schema": {
      "type": "object",
      "properties": {
        "asset_id": { "type": "string" }
      },
      "required": ["asset_id"]
    }
  }
]