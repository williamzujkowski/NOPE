# NOPE Agent Architecture

## Overview

NOPE employs a modular agent-based architecture where each agent has a specific responsibility in the vulnerability processing pipeline. This design ensures fault isolation, parallel execution capability, and easy extensibility.

## Core Agent Types

### 1. Controller Agent (`controller_agent.py`)

**Role**: Master orchestrator for the entire pipeline

**Responsibilities**:
- Manages agent lifecycle and dependencies
- Enforces execution order based on data dependencies
- Aggregates results and metrics from all agents
- Handles error recovery and retry logic

**Key Methods**:
```python
async def run(self, force: bool = False) -> Dict[str, Any]:
    """Execute the complete pipeline with dependency management."""
    
async def health_check() -> Dict[str, Any]:
    """Verify all agents are operational."""
```

### 2. CVE Fetch Agent (`cve_fetch_agent.py`)

**Role**: Data ingestion from vulnerability sources

**Data Sources**:
- CVEProject/cvelistV5 GitHub repository
- GitHub Security Advisory Database
- NVD API (optional fallback)

**Features**:
- 10-day SQLite cache with timezone-aware timestamps
- Incremental fetch support for efficiency
- Automatic retry with exponential backoff
- Response validation and error handling

**Cache Strategy**:
```python
# Cache key format
cache_key = f"cve_fetch_{source}_{date}_{hash}"

# Cache invalidation
if cache_age_days > 10 or force_refresh:
    fetch_fresh_data()
```

### 3. EPSS Filter Agent (`epss_filter_agent.py`)

**Role**: Critical filtering based on exploitation probability

**Threshold**: Default 60% (0.6) exploitation probability

**Processing**:
```python
def filter_vulnerabilities(self, vulns: List[Dict]) -> Tuple[List[Dict], Dict]:
    filtered = []
    for vuln in vulns:
        epss_score = self._extract_epss_score(vuln)
        if epss_score >= self.threshold:
            filtered.append(vuln)
            self.stats["passed_filter"] += 1
        else:
            self.stats["failed_filter"] += 1
    return filtered, self.stats
```

**Validation**:
- Ensures EPSS score exists and is valid (0.0-1.0)
- Logs all filtering decisions for audit trail
- Generates compliance reports

### 4. CISA KEV Agent (`cisa_kev_agent.py`)

**Role**: Enrich with Known Exploited Vulnerabilities data

**Data Source**: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

**Enrichment Fields**:
- `isKnownExploited`: Boolean flag for active exploitation
- `dateAdded`: When added to KEV catalog
- `dueDate`: Federal remediation deadline
- `knownRansomwareCampaignUse`: Ransomware association
- `requiredAction`: CISA-mandated remediation steps

**Cache**: 24-hour TTL for KEV catalog

### 5. Exploit Availability Agent (`exploit_availability_agent.py`)

**Role**: Detect public exploit availability

**Sources Checked**:
- Exploit-DB (via web search)
- Metasploit modules
- GitHub repositories (PoC detection)
- PacketStorm Security

**Enrichment Example**:
```python
{
    "exploitAvailability": {
        "exploitDb": True,
        "metasploit": True,
        "githubPocs": 5,
        "packetStorm": False,
        "exploitMaturity": "functional",
        "firstSeenDate": "2024-03-15"
    }
}
```

**EPSS Percentile Addition**:
- Calculates percentile rank within dataset
- Flags top 1%, 5%, and 10% vulnerabilities
- Adds `isTop1Percent`, `isTop5Percent` boolean flags

### 6. Deps.dev Enrichment Agent (`deps_dev_enrichment_agent.py`)

**Role**: Supply chain impact analysis

**API**: https://deps.dev/api/v3/

**Package Identification**:
1. Parses CVE affected products/vendors
2. Maps to package ecosystems (npm, PyPI, Maven, etc.)
3. Queries deps.dev for dependency counts

**Enrichment Data**:
```python
{
    "packageImpact": {
        "ecosystem": "npm",
        "package": "lodash",
        "versions": ["<4.17.21"],
        "dependentCount": 150000,
        "directDependents": 5000,
        "devDependents": 145000
    }
}
```

### 7. Data Validation Agent (`data_validation_agent.py`)

**Role**: Multi-stage data quality assurance

**Validation Stages**:
1. **Raw**: Initial data structure validation
2. **Filtered**: Post-EPSS filter compliance
3. **Enriched**: Complete enrichment validation
4. **Published**: Final output verification

**Checks Performed**:
- Required fields presence
- Data type validation
- Value range verification
- Cross-field consistency
- EPSS threshold compliance

### 8. Cleanup Agent (`cleanup_agent.py`)

**Role**: Prevent stale data accumulation

**Critical Function**: Removes outdated files that Eleventy incremental builds preserve

**Operations**:
```python
def cleanup_stale_files(self, build_dir: Path, api_dir: Path):
    """Remove files for CVEs no longer in dataset."""
    current_cves = self.get_current_cve_list()
    
    # Clean build directory
    for file in build_dir.glob("cves/CVE-*.html"):
        cve_id = file.stem
        if cve_id not in current_cves:
            file.unlink()
            self.stats["deleted_files"] += 1
    
    # Clean API directory
    # ... similar logic for JSON files
```

**Verification Mode**: Can run in safe mode to preview deletions

### 9. Static Page Agent (`static_page_agent.py`)

**Role**: Generate static site content

**Outputs**:
- Individual CVE detail pages
- Daily briefing posts
- JSON API files (chunked by severity-year)
- Search index for client-side filtering

**Template Processing**:
```python
def generate_cve_page(self, vuln: Dict) -> str:
    """Generate enhanced CVE detail page."""
    return self.template.render(
        cve=vuln,
        enrichments={
            "kev": vuln.get("cisaKev"),
            "exploit": vuln.get("exploitAvailability"),
            "deps": vuln.get("packageImpact")
        }
    )
```

### 10. Dashboard Agent (`dashboard_agent.py`)

**Role**: Generate Alpine.js dashboard data

**Optimizations**:
- Chunks data by severity and year
- Creates search index with Fuse.js config
- Implements virtual scrolling metadata
- Generates chart data for visualizations

**Output Structure**:
```json
{
    "vulnerabilities": [...],
    "metadata": {
        "lastUpdated": "2024-03-20T10:00:00Z",
        "totalCount": 67,
        "severityDistribution": {
            "CRITICAL": 23,
            "HIGH": 44
        },
        "epssStats": {
            "average": 0.725,
            "top1Percent": 15
        }
    }
}
```

### 11. CI Agent (`ci_agent.py`)

**Role**: Build and deployment orchestration

**Functions**:
- Executes npm build commands
- Manages GitHub Pages deployment
- Runs validation checks
- Generates build artifacts

**Quality Gates**:
```python
def validate_build(self) -> bool:
    """Ensure build meets quality standards."""
    checks = [
        self.check_cve_count(max=1000, expected=60),
        self.check_epss_compliance(min=0.6),
        self.check_no_stale_files(),
        self.check_data_integrity()
    ]
    return all(checks)
```

### 12. Threshold Compliance Agent (`threshold_compliance_agent.py`)

**Role**: Enforce EPSS threshold policy

**Critical Check**: Fails CI/CD if any CVE has EPSS < 60%

**Report Generation**:
```python
{
    "compliance": {
        "threshold": 0.6,
        "totalChecked": 67,
        "violations": [],
        "lowestScore": 0.61234,
        "highestScore": 0.98765,
        "status": "PASSED"
    }
}
```

## Agent Communication

### Message Passing

Agents communicate through structured result dictionaries:

```python
# Agent result format
{
    "success": True,
    "data": {...},
    "metadata": {
        "agent": "EPSSFilterAgent",
        "duration": 2.34,
        "timestamp": "2024-03-20T10:00:00Z"
    },
    "errors": [],
    "stats": {
        "processed": 15000,
        "output": 67
    }
}
```

### Dependency Management

Controller Agent manages execution order:

```python
AGENT_DEPENDENCIES = {
    "epss_filter": ["cve_fetch"],
    "cisa_kev": ["epss_filter"],
    "exploit_availability": ["epss_filter"],
    "deps_dev_enrichment": ["epss_filter"],
    "data_validation": ["deps_dev_enrichment"],
    "static_page": ["data_validation"],
    "dashboard": ["data_validation"],
    "ci": ["static_page", "dashboard"]
}
```

## Error Handling

### Retry Strategy

```python
@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10),
    retry=retry_if_exception_type(requests.RequestException)
)
async def fetch_with_retry(self, url: str):
    """Fetch with automatic retry on network errors."""
```

### Graceful Degradation

- Missing EPSS scores: Filter out vulnerability
- API failures: Use cached data if available
- Enrichment failures: Log warning, continue pipeline

## Performance Optimization

### Parallel Execution

```python
# Parallel enrichment after filtering
async def enrich_parallel(self, vulns: List[Dict]):
    tasks = [
        self.cisa_kev_agent.enrich(vulns),
        self.exploit_agent.enrich(vulns),
        self.deps_dev_agent.enrich(vulns)
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
```

### Caching Strategy

- **API Responses**: 10-day SQLite cache
- **KEV Catalog**: 24-hour memory cache
- **Enrichment Results**: 1-hour memory cache
- **Build Artifacts**: GitHub Actions cache

## Monitoring & Metrics

### Agent Metrics

Each agent tracks:
- Execution time
- Success/failure rate
- Data processing volume
- Cache hit rate
- Error frequency

### Health Checks

```python
async def health_check(self) -> Dict[str, Any]:
    return {
        "status": "healthy" if not self.errors else "degraded",
        "uptime": self.uptime_seconds,
        "last_run": self.last_run_time,
        "run_count": self.run_count,
        "error_count": len(self.errors),
        "cache_size": self.get_cache_size()
    }
```

## Extension Points

### Adding New Agents

1. Inherit from `BaseAgent`
2. Implement required methods:
   - `async def run()`
   - `def get_status()`
   - `async def health_check()`
3. Register in `AgentManager`
4. Add to dependency graph

### Custom Enrichment Sources

```python
class CustomEnrichmentAgent(BaseAgent):
    async def enrich(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Add custom enrichment data."""
        for vuln in vulnerabilities:
            vuln["customData"] = await self.fetch_custom_data(vuln["cveId"])
        return vulnerabilities
```

## Best Practices

1. **Idempotency**: Agents should produce same output for same input
2. **Isolation**: Agents should not share mutable state
3. **Logging**: Use structured logging for all operations
4. **Validation**: Validate inputs and outputs at boundaries
5. **Caching**: Implement appropriate caching for external calls
6. **Metrics**: Track performance and reliability metrics
7. **Testing**: Unit test each agent independently

---

The agent architecture provides a robust, scalable foundation for vulnerability processing while maintaining clear separation of concerns and enabling easy maintenance and extension.