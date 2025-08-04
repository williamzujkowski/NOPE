# NOPE: High-Risk CVE Intelligence Platform Architecture

## 1. Mission & Value Proposition

NOPE is a cutting-edge vulnerability intelligence platform designed to **monitor and surface only the highest-risk CVEs** that pose immediate threats to organizations. The system leverages the **Exploit Prediction Scoring System (EPSS)** to filter vulnerabilities with ≥60% exploitation probability, dramatically reducing alert fatigue while ensuring critical threats are never missed.

### Core Value Drivers

- **Predictive Intelligence**: EPSS provides daily-updated exploitation likelihood scores based on real-world threat data, offering 10-100x better prioritization than CVSS alone
- **Automated Enrichment**: Integrates CISA KEV, deps.dev, Exploit-DB, and SSVC data for comprehensive threat context
- **Zero-Infrastructure**: Fully static site deployment requires no backend servers or databases
- **Actionable Insights**: Each vulnerability includes exploitation timeline, patch availability, and package impact analysis

### Why EPSS?

The Exploit Prediction Scoring System (EPSS) leverages machine learning models trained on actual exploitation activity to predict the probability that a vulnerability will be exploited in the wild within 30 days. Unlike CVSS which measures theoretical severity, EPSS focuses on **real-world exploitation likelihood**, enabling security teams to prioritize remediation efforts on vulnerabilities that attackers are actually targeting.

## 2. Data Sources & Intelligence Feeds

### Primary Vulnerability Sources

| Source                          | Purpose                         | Update Frequency   | Integration Method          |
| ------------------------------- | ------------------------------- | ------------------ | --------------------------- |
| **CVEProject/cvelistV5**        | Official CVE List repository    | Every 7 minutes    | Git clone via GitHub API    |
| **GitHub Security Advisory DB** | Enhanced vulnerability metadata | Real-time          | GraphQL API                 |
| **EPSS Daily Feed**             | Exploitation probability scores | Daily at 00:05 UTC | CSV download from FIRST.org |
| **CISA KEV Catalog**            | Known Exploited Vulnerabilities | Daily              | JSON API                    |
| **deps.dev API**                | Package dependency impact       | On-demand          | REST API                    |
| **Exploit-DB**                  | Public exploit availability     | Real-time search   | Web scraping                |
| **SSVC/Vulnrichment**           | CISA enrichment metadata        | Daily              | JSON feed                   |

### Data Enrichment Pipeline

```python
# Example enrichment flow
vulnerability = {
    "cveId": "CVE-2024-1234",
    "cvss": {"baseScore": 9.8},
    # Base CVE data
}

# 1. EPSS enrichment adds exploitation probability
vulnerability["epss"] = {
    "score": 0.76543,  # 76.5% exploitation probability
    "percentile": 0.99  # Top 1% most likely to be exploited
}

# 2. CISA KEV enrichment flags active exploitation
vulnerability["cisaKev"] = {
    "isKnownExploited": True,
    "dateAdded": "2024-03-15",
    "dueDate": "2024-04-05",
    "knownRansomwareCampaignUse": "Known"
}

# 3. deps.dev enrichment adds package impact
vulnerability["packageImpact"] = {
    "ecosystem": "npm",
    "package": "example-lib",
    "versions": ["<2.3.4"],
    "dependentCount": 15000  # Supply chain impact
}

# 4. Exploit availability enrichment
vulnerability["exploitAvailability"] = {
    "exploitDb": True,
    "metasploit": True,
    "githubPocs": 5,
    "exploitMaturity": "functional"
}
```

## 3. Technology Stack & Frameworks

### Core Technologies

- **Static Site Generator**: [Eleventy (11ty)](https://www.11ty.dev/) v2.0.1
  - Builds the `/NOPE/` static site from templates and data
  - **CRITICAL**: Always performs full builds (`npm run build`), never incremental
  - Incremental builds don't delete stale files, causing the 15,000+ CVE issue
  
- **Frontend Framework**: [Alpine.js](https://alpinejs.dev/) v3.14
  - Lightweight reactive framework for client-side filtering and search
  - Zero-build-step integration with excellent performance
  
- **Search Library**: [Fuse.js](https://fusejs.io/) v7.1
  - Fuzzy search across CVE IDs, descriptions, vendors, and products
  - Runs in Web Worker for large datasets (>100 items)
  
- **Python Orchestration**: Agent-based architecture
  - Modular agents for each enrichment source
  - Async execution with error isolation
  - Structured logging via structlog
  
- **Data Validation**: Custom validator with Great Expectations patterns
  - Schema validation at each pipeline stage
  - EPSS threshold enforcement (≥60%)
  - Data quality metrics and reporting
  
- **Testing Frameworks**:
  - **Python**: pytest with 85%+ coverage requirement
  - **E2E**: Playwright for live site validation
  - **JavaScript**: ESLint (Google style) + Prettier

### Agent Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Controller Agent                        │
│                 (Orchestrates Pipeline)                      │
└──────────────────────┬──────────────────────────────────────┘
                       │
        ┌──────────────┴──────────────┬─────────────────┐
        │                             │                 │
┌───────▼────────┐           ┌───────▼────────┐ ┌──────▼──────┐
│ CVEFetchAgent  │           │ EPSSFilterAgent│ │  CIAgent    │
│                │           │                │ │             │
│ - CVEProject   │           │ - EPSS ≥ 60%   │ │ - Gatecheck │
│ - GitHub Adv.  │           │ - Validation   │ │ - Deploy    │
└───────┬────────┘           └───────┬────────┘ └─────────────┘
        │                             │
        └──────────────┬──────────────┘
                       │
        ┌──────────────┴───────────────────────────┐
        │                                          │
┌───────▼────────┐  ┌────────▼────────┐  ┌────────▼────────┐
│ CISAKEVAgent   │  │ DepsDevAgent    │  │ ExploitAgent    │
│                │  │                 │  │                 │
│ - KEV catalog  │  │ - Package deps  │  │ - Exploit-DB    │
│ - Ransomware   │  │ - Supply chain  │  │ - GitHub PoCs   │
└────────────────┘  └─────────────────┘  └─────────────────┘
```

## 4. Architectural Overview / Data Pipeline

### End-to-End Processing Flow

| Stage                    | Technology                         | Purpose                                   | Key Validations                        |
| ------------------------ | ---------------------------------- | ----------------------------------------- | -------------------------------------- |
| **1. Data Ingestion**    | Python Fetch Agents                | Pull CVE feeds, EPSS scores, threat intel | API availability, response validation  |
| **2. EPSS Filtering**    | EPSSFilterAgent                    | Enforce ≥60% exploitation probability     | Threshold compliance, score validation |
| **3. Schema Validation** | Data Validation Agent              | Ensure data structure integrity           | Required fields, type checking         |
| **4. Enrichment**        | CISA KEV, deps.dev, Exploit agents | Add threat context and package impact     | Cross-reference accuracy               |
| **5. Risk Scoring**      | Risk Scorer                        | Calculate 0-100 composite risk score      | Weight validation, score bounds        |
| **6. Static Generation** | Eleventy + Python                  | Build HTML pages and JSON APIs            | File count limits, no stale data       |
| **7. CI Gatecheck**      | `ci_gatecheck.py`                  | Validate CVE count, EPSS compliance       | Max 1000 CVEs, all ≥60% EPSS           |
| **8. Deployment**        | GitHub Actions                     | Force push to gh-pages branch             | Directory purge, cache invalidation    |
| **9. Post-Deploy QA**    | Playwright E2E                     | Validate live site data integrity         | CVE count, enrichment rendering        |

### Risk Score Calculation

```python
def calculate_risk_score(vuln: Dict) -> int:
    """Composite risk score based on multiple factors."""
    score = 0
    
    # CVSS base score (0-40 points)
    cvss_score = vuln.get("cvss", {}).get("baseScore", 0)
    score += (cvss_score / 10) * 40
    
    # EPSS score (0-30 points)
    epss_score = vuln.get("epss", {}).get("score", 0)
    score += epss_score * 30
    
    # CISA KEV status (0-20 points)
    if vuln.get("cisaKev", {}).get("isKnownExploited"):
        score += 20
    
    # Exploit availability (0-10 points)
    exploit_data = vuln.get("exploitAvailability", {})
    if exploit_data.get("exploitDb") or exploit_data.get("metasploit"):
        score += 10
    
    return min(100, int(score))
```

## 5. Deployment & CI/CD Strategy

### Critical Build Requirements

**The #1 Rule**: **NEVER use incremental builds in production**

```bash
# ❌ DANGEROUS - Preserves stale files from previous builds
npx @11ty/eleventy --incremental

# ✅ SAFE - Always clean build
npm run build        # Runs: clean + generate
npm run build:force  # Emergency rebuild with validation
```

### Why Force Purging is Essential

Eleventy's incremental build mode has a critical limitation: **it never deletes files that no longer exist in the source**. This caused the infamous "15,000+ CVE issue" where years of historical CVE pages accumulated on the production site despite EPSS filtering reducing the actual dataset to ~60 CVEs.

### CI/CD Pipeline Stages

1. **Pre-Build Cleanup** (Critical)
   ```python
   python -m scripts.cleanup_stale_files \
     --build-dir _site \
     --api-dir api \
     --force-purge
   ```

2. **Data Harvesting & Enrichment**
   - Fetch latest CVE data with 10-day cache TTL
   - Apply EPSS ≥60% filter immediately
   - Enrich with CISA KEV, deps.dev, exploits
   - Validate at each stage

3. **Quality Gates**
   - **CVE Count Check**: Fail if >1000 CVEs (expected ~60)
   - **EPSS Compliance**: Fail if any CVE <60% EPSS
   - **Data Validation**: Schema compliance at 4 stages
   - **Stale File Detection**: Verify no outdated pages

4. **Deployment**
   ```bash
   # Complete directory replacement
   rm -rf gh-pages/*
   cp -r public/* gh-pages/
   git push --force-with-lease origin gh-pages
   ```

5. **Post-Deploy Validation**
   - Wait 2 minutes for CDN propagation
   - Playwright tests verify live data
   - Alert on threshold violations

### GitHub Actions Workflows

- **`scheduled-harvest.yml`**: Main 4-hour harvest cycle
- **`post-deploy-qa.yml`**: Automated live site validation
- **`quality-gates.yml`**: Pre-commit validation hooks
- **`ci.yml`**: PR validation and testing

## 6. Desktop & Mobile UX/UI Guidelines

### Performance Requirements

- **Search Response**: <100ms for ~60 CVE dataset
- **Filter Updates**: Debounced at 300ms
- **Page Load**: <3s on 3G networks
- **Lighthouse Score**: >90 Performance

### Mobile Optimizations

```css
/* 40% density improvement on mobile */
@media (max-width: 768px) {
  .vuln-card {
    padding: 0.75rem;  /* Reduced from 1.5rem */
    font-size: 0.875rem;
  }
  
  /* Auto-hide filters after selection */
  .filter-panel[data-filtered="true"] {
    transform: translateY(-100%);
  }
}
```

### Accessibility Features

- **Keyboard Navigation**: Full support (Tab, Arrow keys, Esc)
- **Screen Readers**: ARIA labels and live regions
- **High Contrast**: CSS custom properties for theming
- **Focus Management**: Proper focus trapping in modals

### Visual Indicators

```typescript
// Badge components for threat intelligence
<span class="badge badge--kev" title="CISA Known Exploited">
  KEV Active
</span>

<span class="badge badge--exploit" title="Public exploit available">
  Exploit Available
</span>

<span class="badge badge--supply-chain" title="15,000+ dependent packages">
  High Impact
</span>
```

## 7. Maintenance & Emergency Procedures

### Updating EPSS Threshold

To change from 60% to 70% threshold:

1. **Update environment variable**:
   ```yaml
   # .github/workflows/scheduled-harvest.yml
   env:
     EPSS_THRESHOLD: "0.7"
   ```

2. **Update validation scripts**:
   ```bash
   # All scripts that reference --min-epss
   grep -r "min-epss 0.6" scripts/ .github/
   # Update to --min-epss 0.7
   ```

3. **Force rebuild to purge old data**:
   ```bash
   npm run build:force
   npm run deploy
   ```

### Emergency Stale Data Flush

If production shows >1000 CVEs:

```bash
# 1. Immediate force rebuild
python -m scripts.force_rebuild \
  --expected-count 60 \
  --min-epss 0.6

# 2. Manual GitHub Pages cache clear
curl -X POST \
  -H "Authorization: token $GITHUB_TOKEN" \
  https://api.github.com/repos/$OWNER/$REPO/pages/builds

# 3. Verify fix after 10 minutes
pytest tests/e2e/test_live_site_sanity.py
```

### Rollback Procedure

```bash
# 1. Identify last known good commit
git log --oneline -n 20

# 2. Force reset gh-pages branch
git checkout gh-pages
git reset --hard <good-commit-sha>
git push --force origin gh-pages

# 3. Trigger fresh build
gh workflow run scheduled-harvest.yml
```

## 8. Standards Alignment & Auditing Integration

### Security Standards Compliance

| Standard                  | Implementation                                  | Audit Trail                  |
| ------------------------- | ----------------------------------------------- | ---------------------------- |
| **CS** (Code Standards)   | ESLint, Ruff linting with zero-error policy     | CI logs, git hooks           |
| **TS** (Test Standards)   | 85%+ coverage, no skipped tests                 | coverage.xml, pytest reports |
| **SEC** (Security)        | Bandit scanning, TruffleHog secrets detection   | Security scan artifacts      |
| **DE** (Data Engineering) | Great Expectations patterns, 4-stage validation | Data quality reports         |
| **FE** (Frontend)         | Lighthouse CI, WCAG 2.1 AA compliance           | Lighthouse reports           |
| **DOP** (DevOps)          | Immutable deployments, forced rebuilds          | GitHub Actions logs          |
| **NIST-IG** (Governance)  | Threshold decision logging, CLI audit flags     | --fail-on-violations logs    |

### Audit Logging

Every threshold decision and data modification is logged:

```python
# Example audit log entry
{
    "timestamp": "2024-03-15T10:30:00Z",
    "action": "epss_filter",
    "threshold": 0.6,
    "input_count": 15234,
    "output_count": 67,
    "filtered_out": 15167,
    "agent": "EPSSFilterAgent",
    "run_id": "abc123",
    "violations": []
}
```

### Compliance Validation Commands

```bash
# Generate compliance report
python -m scripts.main validate-threshold-compliance \
  --api-dir api \
  --min-epss 0.6 \
  --output-report compliance-$(date +%Y%m%d).json

# Audit trail for threshold changes
git log -p -- scripts/agents/epss_filter_agent.py | \
  grep -E "(threshold|EPSS_THRESHOLD)"
```

## 9. Appendices

### A. Sample EPSS Filtering Query

```sql
-- SQLite query for EPSS filtering
SELECT 
    cve_id,
    cvss_score,
    epss_score,
    epss_percentile,
    cisa_kev_status,
    exploit_available
FROM vulnerabilities
WHERE epss_score >= 0.6
  AND severity IN ('CRITICAL', 'HIGH')
  AND year >= 2024
ORDER BY epss_score DESC, cvss_score DESC
LIMIT 100;
```

### B. CVE Record Schema (Post-Enrichment)

```json
{
  "cveId": "CVE-2024-1234",
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
  "cisaKev": {
    "isKnownExploited": true,
    "dateAdded": "2024-03-15",
    "knownRansomwareCampaignUse": "Known"
  },
  "exploitAvailability": {
    "exploitDb": true,
    "metasploit": true,
    "githubPocs": 5
  },
  "packageImpact": {
    "ecosystem": "npm",
    "package": "example-lib",
    "dependentCount": 15000
  },
  "riskScore": 95,
  "published": "2024-03-10T00:00:00Z"
}
```

### C. Sample Playwright E2E Test

```python
async def test_cisa_kev_badge_display(page):
    """Verify CISA KEV badges render correctly."""
    await page.goto("https://williamzujkowski.github.io/NOPE/")
    
    # Wait for data to load
    await page.wait_for_selector(".vuln-table", timeout=10000)
    
    # Find CVE with KEV badge
    kev_badge = await page.query_selector(".badge--kev")
    assert kev_badge is not None, "No CISA KEV badges found"
    
    # Verify badge text
    badge_text = await kev_badge.inner_text()
    assert "KEV" in badge_text
    
    # Verify tooltip
    title = await kev_badge.get_attribute("title")
    assert "Known Exploited" in title
```

---

## Summary

NOPE represents a modern approach to vulnerability intelligence, combining predictive analytics (EPSS) with comprehensive threat enrichment to deliver actionable security insights. The architecture prioritizes reliability through forced clean builds, data quality through multi-stage validation, and operational efficiency through static site deployment. With its focus on high-risk vulnerabilities (EPSS ≥60%), the platform enables security teams to concentrate on the threats that matter most.