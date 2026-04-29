Here are all 6 tools:

---

**1. `get_ip_reputation`**
```json
{
  "name": "get_ip_reputation",
  "description": "Check the reputation and threat intelligence of an IP address. Use this whenever an alert contains a source or destination IP to determine if it is known malicious, suspicious, or clean.",
  "input_schema": {
    "type": "object",
    "properties": {
      "ip": {
        "type": "string",
        "description": "The IPv4 or IPv6 address to check"
      }
    },
    "required": ["ip"]
  }
}
```

---

**2. `get_domain_reputation`**
```json
{
  "name": "get_domain_reputation",
  "description": "Check the reputation of a domain or URL. Use this when an alert involves suspicious outbound connections, DNS lookups, or phishing-related activity.",
  "input_schema": {
    "type": "object",
    "properties": {
      "domain": {
        "type": "string",
        "description": "The domain name or URL to check e.g. malware.example.com"
      }
    },
    "required": ["domain"]
  }
}
```

---

**3. `get_asset_history`**
```json
{
  "name": "get_asset_history",
  "description": "Retrieve past alerts and incidents associated with a specific asset (hostname or IP) from the AegisAI database. Use this to determine if the asset has a history of suspicious behaviour or is a repeat offender.",
  "input_schema": {
    "type": "object",
    "properties": {
      "asset": {
        "type": "string",
        "description": "The hostname or IP address of the asset"
      },
      "limit": {
        "type": "number",
        "description": "Max number of past alerts to return. Default 10."
      }
    },
    "required": ["asset"]
  }
}
```

---

**4. `get_user_history`**
```json
{
  "name": "get_user_history",
  "description": "Retrieve past alerts and incidents associated with a specific user from the AegisAI database. Use this when an alert involves a user account to check if they have a history of suspicious activity.",
  "input_schema": {
    "type": "object",
    "properties": {
      "username": {
        "type": "string",
        "description": "The username or email of the user to look up"
      },
      "limit": {
        "type": "number",
        "description": "Max number of past alerts to return. Default 10."
      }
    },
    "required": ["username"]
  }
}
```

---

**5. `query_rapid7_logs`**
```json
{
  "name": "query_rapid7_logs",
  "description": "Run a LEQL query against Rapid7 InsightIDR log data to retrieve surrounding log context for an alert. Use this to find related events, trace attack chains, or gather evidence. You must write a valid LEQL query.",
  "input_schema": {
    "type": "object",
    "properties": {
      "leql": {
        "type": "string",
        "description": "A valid LEQL query string e.g. where(source_ip=192.168.1.1) or where(user=john.doe AND action=LOGIN_FAILED)"
      },
      "time_range": {
        "type": "string",
        "description": "Time range for the query. Use relative values: Last 1 Hour, Last 24 Hours, Last 7 Days, Today, Yesterday",
        "enum": ["Last 1 Hour", "Last 24 Hours", "Last 7 Days", "Today", "Yesterday"]
      },
      "log_ids": {
        "type": "array",
        "items": { "type": "string" },
        "description": "Optional list of specific log IDs to query. If omitted, queries across all available logs."
      }
    },
    "required": ["leql", "time_range"]
  }
}
```

---

**6. `generate_triage_report`**
```json
{
  "name": "generate_triage_report",
  "description": "Call this tool ONLY when you have gathered sufficient evidence from all other tools and are ready to submit the final triage verdict. This ends the investigation.",
  "input_schema": {
    "type": "object",
    "properties": {
      "verdict": {
        "type": "string",
        "enum": ["true_positive", "false_positive", "escalate"],
        "description": "The final verdict of the investigation"
      },
      "severity": {
        "type": "string",
        "enum": ["critical", "high", "medium", "low", "informational"],
        "description": "Severity level of the alert"
      },
      "summary": {
        "type": "string",
        "description": "Plain English explanation of what happened, suitable for a non-technical stakeholder"
      },
      "attack_chain": {
        "type": "array",
        "items": { "type": "string" },
        "description": "Ordered list of steps describing the attack chain e.g. ['Phishing email received', 'User clicked link', 'Malware dropped']"
      },
      "mitre_technique": {
        "type": "string",
        "description": "The most relevant MITRE ATT&CK technique ID e.g. T1059.001. Leave empty if not applicable."
      },
      "affected_assets": {
        "type": "array",
        "items": { "type": "string" },
        "description": "List of hostnames or IPs of affected assets"
      },
      "affected_users": {
        "type": "array",
        "items": { "type": "string" },
        "description": "List of usernames or emails of affected users"
      },
      "recommended_action": {
        "type": "string",
        "description": "What the SOC analyst should do next e.g. isolate asset, reset credentials, close as false positive"
      },
      "confidence": {
        "type": "string",
        "enum": ["high", "medium", "low"],
        "description": "How confident Claude is in this verdict based on evidence gathered"
      }
    },
    "required": ["verdict", "severity", "summary", "attack_chain", "recommended_action", "confidence"]
  }
}
```

---

**The trick with `generate_triage_report`** is that it's not a real tool that calls an API — it's a forcing function. When Claude calls it, that's your signal that the investigation is done. You extract the `tool_input` from that call, that IS your triage report, save it to DB and fire the final SSE. You never actually execute anything for this tool — you just catch it in your switch and end the loop.

So your switch case looks like:

```typescript
switch (toolName) {
  case "get_ip_reputation":      return await getIpReputation(input.ip);
  case "get_domain_reputation":  return await getDomainReputation(input.domain);
  case "get_asset_history":      return await getAssetHistory(input.asset, input.limit);
  case "get_user_history":       return await getUserHistory(input.username, input.limit);
  case "query_rapid7_logs":      return await queryRapid7Logs(input.leql, input.time_range, input.log_ids);
  case "generate_triage_report": return "DONE"; // loop ends here, input = your report
}
```

Ready to implement `ai.agent.ts` now?