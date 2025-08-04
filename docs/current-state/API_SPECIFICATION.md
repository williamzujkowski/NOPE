# NOPE API Specification

## Overview

The NOPE API provides access to predictive CVE intelligence data through static JSON files served via GitHub Pages. All endpoints return pre-generated JSON data updated every 4 hours by the prediction pipeline.

## Base URL

**Production**: `https://williamzujkowski.github.io/NOPE/api/`  
**Development**: `http://localhost:8080/api/`

## Authentication

No authentication required - all data is publicly accessible.

## Rate Limiting

GitHub Pages rate limits apply:
- 100GB bandwidth/month
- No request rate limits

## API Endpoints

### 1. Latest Predictions

**GET** `/api/predictions/latest.json`

Returns the most recent CVE predictions with risk scores and ML model contributions.

**Response Format:**
```json
{
  "generated_at": "2024-03-20T10:00:00Z",
  "metadata": {
    "total_count": 67,
    "epss_threshold": 0.10,
    "model_version": "2.0",
    "accuracy_rate": 0.875
  },
  "predictions": [
    {
      "cve_id": "CVE-2024-12345",
      "severity": "CRITICAL",
      "cvss": {
        "baseScore": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      },
      "epss": {
        "score": 0.76543,
        "percentile": 0.99234,
        "isTop1Percent": true
      },
      "risk_score": 92,
      "confidence": 0.87,
      "will_be_exploited": true,
      "time_to_exploitation": 7,
      "threat_level": "CRITICAL",
      "key_risk_factors": [
        {
          "factor": "Velocity Model",
          "description": "Rapidly increasing exploitation likelihood",
          "severity": "high",
          "contribution": 0.22
        },
        {
          "factor": "Threat Actor Model",
          "description": "Matches known threat actor preferences",
          "severity": "high",
          "contribution": 0.20
        }
      ],
      "model_contributions": {
        "epss_enhanced": 0.85,
        "velocity_model": 0.91,
        "threat_actor_model": 0.88,
        "temporal_model": 0.72,
        "practicality_model": 0.79,
        "community_model": 0.83,
        "pattern_model": 0.76
      },
      "enrichments": {
        "cisaKev": {
          "isKnownExploited": true,
          "dateAdded": "2024-03-15",
          "dueDate": "2024-04-05",
          "knownRansomwareCampaignUse": "Known"
        },
        "exploitAvailability": {
          "exploitDb": true,
          "metasploit": true,
          "githubPocs": 5,
          "exploitMaturity": "functional"
        },
        "packageImpact": {
          "ecosystem": "npm",
          "package": "example-lib",
          "versions": ["<2.3.4"],
          "dependentCount": 15000
        }
      },
      "recommendation": "IMMEDIATE ACTION REQUIRED: Patch within 24 hours",
      "published": "2024-03-10T00:00:00Z",
      "modified": "2024-03-20T08:00:00Z"
    }
  ]
}
```

**Query Parameters:**
- `severity` - Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
- `risk_min` - Minimum risk score (0-100)
- `exploited` - Filter by exploitation status (true/false)

**Example:**
```bash
curl https://williamzujkowski.github.io/NOPE/api/predictions/latest.json?severity=CRITICAL&risk_min=80
```

### 2. Early Warning Alerts

**GET** `/api/early-warnings.json`

Returns vulnerabilities showing early exploitation signals (14-21 days advance warning).

**Response Format:**
```json
{
  "generated_at": "2024-03-20T10:00:00Z",
  "warnings": [
    {
      "cve_id": "CVE-2024-23456",
      "warning_score": 0.72,
      "warning_level": "HIGH",
      "signals_detected": [
        "velocity_increase",
        "community_chatter",
        "poc_development"
      ],
      "estimated_days_to_exploitation": 14,
      "confidence": 0.68,
      "reason": "EPSS velocity increased 0.15 in 7 days, community activity spike",
      "first_signal_date": "2024-03-13T00:00:00Z",
      "recommendation": "Monitor closely and plan patching"
    }
  ],
  "summary": {
    "total_warnings": 12,
    "high_confidence": 5,
    "by_days": {
      "7_days": 2,
      "14_days": 5,
      "21_days": 5
    }
  }
}
```

### 3. Accuracy Metrics

**GET** `/api/metrics/accuracy.json`

Returns model performance metrics and accuracy tracking.

**Response Format:**
```json
{
  "generated_at": "2024-03-20T10:00:00Z",
  "period": "30_days",
  "overall_metrics": {
    "accuracy_rate": 0.875,
    "precision": 0.823,
    "recall": 0.912,
    "f1_score": 0.865,
    "false_positive_rate": 0.225,
    "true_positives": 156,
    "false_positives": 44,
    "true_negatives": 892,
    "false_negatives": 15
  },
  "model_performance": {
    "epss_enhanced": {
      "accuracy": 0.812,
      "contribution": 0.20
    },
    "velocity_model": {
      "accuracy": 0.887,
      "contribution": 0.15
    },
    "threat_actor_model": {
      "accuracy": 0.901,
      "contribution": 0.20
    }
  },
  "accuracy_timeline": [
    {
      "date": "2024-03-20",
      "accuracy": 0.882,
      "precision": 0.831,
      "recall": 0.918
    }
  ],
  "prediction_distribution": {
    "total_predictions": 1107,
    "exploited_confirmed": 171,
    "pending_validation": 45,
    "false_alarms": 44
  }
}
```

### 4. Active Threats

**GET** `/api/threats/active.json`

Returns currently active high-risk threats requiring immediate attention.

**Response Format:**
```json
{
  "generated_at": "2024-03-20T10:00:00Z",
  "active_threats": [
    {
      "cve_id": "CVE-2024-12345",
      "threat_status": "ACTIVE_EXPLOITATION",
      "risk_score": 95,
      "exploitation_confirmed": true,
      "first_seen": "2024-03-18T00:00:00Z",
      "attack_vectors": ["remote", "unauthenticated"],
      "affected_products": [
        {
          "vendor": "Example Corp",
          "product": "Example Server",
          "versions": ["< 2.5.0"]
        }
      ],
      "iocs": {
        "ip_addresses": ["192.0.2.1", "192.0.2.2"],
        "domains": ["malicious.example.com"],
        "file_hashes": []
      },
      "mitigation": {
        "patch_available": true,
        "patch_url": "https://example.com/security/patch-123",
        "workaround": "Disable remote access until patched"
      }
    }
  ],
  "threat_summary": {
    "critical_threats": 3,
    "high_threats": 8,
    "under_active_attack": 2,
    "patch_available": 9
  }
}
```

### 5. Bulk Data Export

**GET** `/api/export/predictions-{YYYY-MM-DD}.json`

Daily export of all predictions for archival/analysis.

**Response Format:**
```json
{
  "export_date": "2024-03-20",
  "format_version": "1.0",
  "total_records": 67,
  "predictions": [...] // Full prediction objects
}
```

## Response Codes

Since these are static files served by GitHub Pages:
- **200 OK** - File exists and returned successfully
- **404 Not Found** - File doesn't exist
- **304 Not Modified** - Cached version is current

## Data Update Schedule

- **Predictions**: Every 4 hours (00:00, 04:00, 08:00, 12:00, 16:00, 20:00 UTC)
- **Early Warnings**: Every 4 hours
- **Metrics**: Daily at 00:05 UTC
- **Active Threats**: Real-time updates when available

## Client Libraries

### JavaScript/TypeScript
```javascript
// Using fetch
const response = await fetch('https://williamzujkowski.github.io/NOPE/api/predictions/latest.json');
const data = await response.json();

// Using axios
import axios from 'axios';
const { data } = await axios.get('https://williamzujkowski.github.io/NOPE/api/predictions/latest.json');
```

### Python
```python
import requests

response = requests.get('https://williamzujkowski.github.io/NOPE/api/predictions/latest.json')
data = response.json()

# With pandas
import pandas as pd
df = pd.read_json('https://williamzujkowski.github.io/NOPE/api/predictions/latest.json')
```

### cURL
```bash
# Get latest predictions
curl https://williamzujkowski.github.io/NOPE/api/predictions/latest.json

# Pretty print with jq
curl https://williamzujkowski.github.io/NOPE/api/predictions/latest.json | jq '.'

# Filter high risk only
curl https://williamzujkowski.github.io/NOPE/api/predictions/latest.json | \
  jq '.predictions[] | select(.risk_score > 80)'
```

## Webhooks (Planned)

Future webhook support for real-time notifications:

```json
{
  "event": "high_risk_detected",
  "timestamp": "2024-03-20T10:00:00Z",
  "data": {
    "cve_id": "CVE-2024-12345",
    "risk_score": 95,
    "action_required": "immediate_patch"
  }
}
```

## Best Practices

1. **Cache responses** - Data updates every 4 hours
2. **Use ETags** - Check if data has changed
3. **Handle 404s** - Files may be regenerating
4. **Parse dates** - All timestamps in ISO 8601 format
5. **Validate schema** - Use JSON schema validation

## API Versioning

Currently v1 (implicit). Future versions will use:
- `/api/v2/predictions/latest.json`

## Support

- GitHub Issues: https://github.com/williamzujkowski/NOPE/issues
- Documentation: https://williamzujkowski.github.io/NOPE/docs
- Status Page: https://williamzujkowski.github.io/NOPE/status