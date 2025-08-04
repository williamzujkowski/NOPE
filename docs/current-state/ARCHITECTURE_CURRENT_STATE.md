# NOPE Architecture - Current State Documentation

## Project Overview

**NOPE (Network Operational Patch Evaluator)** is a cutting-edge predictive CVE intelligence platform that transforms the overwhelming task of reviewing 40,009+ annual CVEs into a manageable set of ~5-8 daily high-confidence predictions with 14-21 days advance warning before exploitation.

### Key Metrics
- **Input**: ~40,009 CVEs annually (110 daily)
- **Output**: ~5-8 high-confidence predictions daily
- **Accuracy Target**: 85-90% exploitation detection
- **Advance Warning**: 14-21 days before exploitation
- **False Positive Rate**: 20-25% (vs 60% traditional)
- **EPSS Threshold**: 0.10 (88th percentile) - dynamically adjusted

### Technology Stack Summary
- **Backend**: Python 3.12 with asyncio agent architecture
- **ML Framework**: 7-model ensemble (scikit-learn, XGBoost, LightGBM, CatBoost)
- **Frontend**: Eleventy 3.0.0 static site generator with Alpine.js 3.14
- **Database**: SQLite (caching), PostgreSQL (production), Redis (real-time)
- **Deployment**: GitHub Actions CI/CD → GitHub Pages
- **Monitoring**: Prometheus + Grafana
- **Container**: Docker Compose multi-service orchestration

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           NOPE Architecture                              │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  External APIs  │     │   GitHub Pages  │     │    Monitoring   │
│  - CVE Sources  │     │   Static Site   │     │  - Prometheus   │
│  - EPSS Feed    │────▶│   - Dashboard   │◀────│  - Grafana      │
│  - CISA KEV     │     │   - Analytics   │     │  - Alerts       │
│  - deps.dev     │     │   - API JSON    │     └─────────────────┘
└────────┬────────┘     └────────▲────────┘
         │                       │
         │                       │ Deploy
         ▼                       │
┌─────────────────────────────────────────────────────────────────────────┐
│                        Agent Pipeline (Python)                           │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌────────────┐    ┌──────────────┐    ┌───────────────┐              │
│  │Controller  │───▶│ CVE Fetch    │───▶│ EPSS Filter   │              │
│  │Agent       │    │ Agent        │    │ Agent (0.10+) │              │
│  └────────────┘    └──────────────┘    └───────┬───────┘              │
│                                                  │                       │
│  ┌────────────────────────────────────┐         │                       │
│  │       Enrichment Agents            │◀────────┘                       │
│  ├────────────────────────────────────┤                                │
│  │ • CISA KEV Agent                   │                                │
│  │ • deps.dev Agent                   │                                │
│  │ • Exploit Availability Agent       │                                │
│  └────────────────┬───────────────────┘                                │
│                   │                                                     │
│  ┌────────────────▼───────────────────┐    ┌─────────────────┐        │
│  │    ML Prediction Pipeline          │    │  Risk Scoring    │        │
│  ├────────────────────────────────────┤    │  Agent (0-100)  │        │
│  │ 7-Model Ensemble:                  │───▶└─────────────────┘        │
│  │ • EPSS Enhanced                    │                                │
│  │ • Velocity Model                   │    ┌─────────────────┐        │
│  │ • Threat Actor                     │    │ Data Validation │        │
│  │ • Temporal                         │───▶│     Agent       │        │
│  │ • Practicality                     │    └─────────────────┘        │
│  │ • Community                        │                                │
│  │ • Pattern                          │                                │
│  └────────────────────────────────────┘                                │
└─────────────────────────────────────────────────────────────────────────┘
         │                                              │
         ▼                                              ▼
┌─────────────────┐                          ┌─────────────────┐
│   Data Layer    │                          │  Static Build   │
├─────────────────┤                          ├─────────────────┤
│ • SQLite Cache  │                          │ • Eleventy SSG  │
│ • Redis Queue   │                          │ • Alpine.js     │
│ • File Storage  │                          │ • API JSON      │
└─────────────────┘                          └─────────────────┘
```

## Directory Structure Analysis

```
/home/william/git/NOPE/
├── .github/workflows/          # CI/CD pipelines
│   ├── ci.yml                 # PR validation workflow
│   └── prediction-pipeline.yml # Main prediction cycle (4hr)
├── config/                    # Configuration files
├── data/                      # Data storage
│   ├── cache/                # SQLite cache files
│   ├── models/               # Trained ML models
│   ├── predictions/          # Prediction outputs
│   └── metrics/              # Performance metrics
├── docker/                   # Docker configuration
├── docs/                     # Documentation
│   ├── architecture/         # Architecture docs
│   └── current-state/        # This documentation
├── examples/                 # Usage examples
│   └── ml_ensemble_example.py
├── notebooks/                # Jupyter notebooks
├── scripts/                  # Utility scripts
├── site/                     # Frontend (Eleventy)
│   ├── _data/               # Global data files
│   ├── _includes/           # Templates
│   │   ├── components/      # UI components
│   │   ├── layouts/         # Page layouts
│   │   └── partials/        # Reusable parts
│   ├── api/                 # API JSON endpoints
│   ├── assets/              # Static assets
│   │   ├── css/            # Stylesheets
│   │   ├── js/             # JavaScript
│   │   └── images/         # Images
│   ├── *.njk               # Page templates
│   └── .eleventy.js        # Eleventy config
├── src/                     # Python source code
│   ├── agents/              # Agent implementations
│   │   ├── enrichment/      # Data enrichment agents
│   │   ├── validation/      # Validation agents
│   │   └── *.py            # Core agents
│   ├── ml/                  # Machine learning
│   │   ├── models/         # 7 prediction models
│   │   ├── features/       # Feature extraction
│   │   └── utils/          # ML utilities
│   ├── config/             # Configuration
│   └── utils/              # Utilities
├── tests/                   # Test suites
│   ├── unit/               # Unit tests
│   ├── integration/        # Integration tests
│   ├── ml/                 # ML model tests
│   └── e2e/                # End-to-end tests
├── pyproject.toml          # Python project config
├── package.json            # Node.js config
├── docker-compose.yml      # Container orchestration
├── Makefile                # Build commands
├── .env.example            # Environment template
└── LICENSE                 # MIT license
```

### Key Files and Their Functions

| File | Purpose |
|------|---------|
| `pyproject.toml` | Python dependencies, build config, linting rules |
| `package.json` | Node.js dependencies, build scripts |
| `.eleventy.js` | Static site generator configuration |
| `docker-compose.yml` | Multi-service container setup |
| `Makefile` | Common commands (build, test, deploy) |
| `.env.example` | Environment variable template |
| `.github/workflows/prediction-pipeline.yml` | Main CI/CD pipeline |

## Backend Components

### Python Agents (10 implemented)

1. **Controller Agent** (`src/agents/controller_agent.py`)
   - Orchestrates entire pipeline execution
   - Manages agent dependencies and ordering
   - Handles error recovery and retries
   - Generates final outputs

2. **CVE Fetch Agent** (`src/agents/cve_fetch_agent.py`)
   - Fetches from CVEProject/cvelistV5, GitHub Advisory DB
   - Implements 10-day SQLite caching
   - Handles incremental updates
   - Rate limiting and retry logic

3. **EPSS Filter Agent** (`src/agents/epss_filter_agent.py`)
   - Applies dynamic EPSS threshold (default 0.10)
   - Adjusts thresholds based on volume
   - Special handling for network devices, ransomware
   - Tracks filtering statistics

4. **CISA KEV Agent** (`src/agents/enrichment/cisa_kev_agent.py`)
   - Enriches with Known Exploited Vulnerabilities
   - Tracks ransomware campaigns
   - Federal remediation deadlines
   - 24-hour cache TTL

5. **deps.dev Agent** (`src/agents/enrichment/depsdev_agent.py`)
   - Supply chain impact analysis
   - Package ecosystem detection
   - Dependency count tracking
   - Rate-limited API calls

6. **Exploit Availability Agent** (`src/agents/enrichment/exploit_availability_agent.py`)
   - Checks Exploit-DB, Metasploit, GitHub
   - Exploit maturity assessment
   - Weaponization level tracking
   - Public vs private exploits

7. **Data Validation Agent** (`src/agents/validation/data_validation_agent.py`)
   - 4-stage validation pipeline
   - Schema compliance checking
   - Data quality metrics
   - Great Expectations patterns

8. **Risk Scorer Agent** (`src/agents/validation/risk_scorer_agent.py`)
   - Composite 0-100 risk scoring
   - Weighted factors: CVSS (25%), EPSS (35%), KEV (20%), Exploits (15%), Supply Chain (5%)
   - Temporal decay factors
   - Risk level recommendations

9. **Base Agent** (`src/agents/base_agent.py`)
   - Abstract base class for all agents
   - Health check interface
   - Caching utilities
   - Structured logging

10. **Additional Agents** (in `src/nope/agents/`)
    - `data_collection.py` - Alternative data collection
    - `analysis.py` - Analysis agent
    - `correlation.py` - Correlation agent

### ML Models and Prediction Pipeline

#### 7-Model Ensemble (`src/ml/models/`)

1. **EPSS Enhanced Model** (`epss_enhanced_model.py`)
   - Improves base EPSS with additional features
   - CVSS integration
   - Vulnerability type analysis

2. **Velocity Model** (`velocity_model.py`)
   - Tracks exploitation speed
   - EPSS score rate of change
   - Acceleration detection

3. **Threat Actor Model** (`threat_actor_model.py`)
   - Actor capability assessment
   - Target preference modeling
   - Campaign correlation

4. **Temporal Model** (`temporal_model.py`)
   - Time-based patterns
   - Seasonal trends
   - Patch Tuesday effects

5. **Practicality Model** (`practicality_model.py`)
   - Technical feasibility
   - Exploit complexity
   - Barrier assessment

6. **Community Model** (`community_model.py`)
   - Security researcher activity
   - Social media signals
   - Forum discussions

7. **Pattern Model** (`pattern_model.py`)
   - Historical pattern matching
   - Similar vulnerability analysis
   - Exploit chain detection

#### ML Utilities (`src/ml/utils/`)

- **model_utils.py** - Model persistence, versioning
- **training_pipeline.py** - Training orchestration
- **correlation_engine.py** - Real-time signal correlation
- **feature_extractor.py** - 100+ feature extraction

### Data Processing Flow

1. **Input Sources**
   - CVEProject/cvelistV5 (GitHub)
   - GitHub Security Advisory Database
   - EPSS daily feed (FIRST.org)
   - CISA KEV catalog
   - deps.dev API

2. **Processing Stages**
   - Data ingestion (10-day cache)
   - EPSS filtering (≥0.10)
   - Multi-source enrichment
   - ML prediction (7 models)
   - Risk scoring (0-100)
   - Validation checks
   - Output generation

3. **Output Formats**
   - JSON API files
   - Static HTML pages
   - Prediction summaries
   - Metrics reports

## Frontend Components

### Static Site Generation (Eleventy)

**Configuration** (`site/.eleventy.js`)
- Full builds only (no incremental)
- Custom filters for CVE formatting
- API data generation
- Performance optimizations

### Page Templates (`site/*.njk`)

1. **index.njk** - Main dashboard
2. **dashboard.njk** - Advanced analytics
3. **predictions.njk** - All predictions view
4. **early-warnings.njk** - 14-21 day warnings
5. **analytics.njk** - Performance metrics

### UI Components (`site/_includes/components/`)

1. **nope-card.njk** - CVE prediction card
   - Risk visualization
   - Model contributions
   - Key risk factors
   - Action buttons

2. **early-warning-alert.njk** - Alert component
   - Real-time notifications
   - Threat summaries
   - Action items

### JavaScript (`site/assets/js/`)

**prediction-engine.js** - Main dashboard engine
- Alpine.js reactive data
- WebSocket real-time updates
- Fuse.js fuzzy search
- Chart.js visualizations
- D3.js timeline charts

### API Endpoints (`site/api/`)

Generated JSON files:
- `/api/predictions/latest.json` - Current predictions
- `/api/early-warnings.json` - Early warning alerts
- `/api/metrics/accuracy.json` - Model performance
- `/api/threats/active.json` - Active threats

## Data Models and Schemas

### CVE Data Structure
```json
{
  "cve_id": "CVE-2024-12345",
  "severity": "CRITICAL",
  "cvss": {
    "baseScore": 9.8,
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  },
  "epss": {
    "score": 0.76543,
    "percentile": 0.99234
  },
  "risk_score": 85,
  "confidence": 0.87,
  "will_be_exploited": true,
  "time_to_exploitation": 14
}
```

### Prediction Result Format
```json
{
  "risk_score": 85.5,
  "confidence": 0.87,
  "will_be_exploited": true,
  "time_to_exploitation": 14,
  "key_risk_factors": [
    {
      "factor": "Velocity Model",
      "description": "Rapidly increasing exploitation likelihood",
      "severity": "high",
      "contribution": 0.22
    }
  ],
  "model_contributions": {
    "epss_enhanced": 0.85,
    "velocity_model": 0.91,
    "threat_actor_model": 0.78
  },
  "recommendation": "HIGH PRIORITY: Schedule patching within 48 hours"
}
```

## Testing Infrastructure

### Test Coverage
- **Target**: 85%+ coverage
- **Current**: Tests configured but implementation in progress

### Test Suites Location
- **Unit Tests**: `tests/unit/` - Component-level testing
- **Integration Tests**: `tests/integration/` - Agent pipeline tests
- **ML Tests**: `tests/ml/` - Model validation
- **E2E Tests**: `tests/e2e/` - Full system tests

### Test Configuration
- pytest with asyncio support
- Coverage reporting (HTML + terminal)
- Benchmark tests for performance
- Playwright for E2E testing

## Deployment Configuration

### GitHub Actions Workflows

1. **prediction-pipeline.yml** - Main workflow
   - Schedule: Every 4 hours
   - Dynamic threshold calculation
   - ML prediction execution
   - Site generation and deployment
   - Metrics export

2. **ci.yml** - PR validation
   - Python/JS linting
   - Unit test execution
   - Security scanning
   - Build validation

### Build Process
1. Install dependencies (Python + Node.js)
2. Download ML models
3. Run security scans
4. Execute prediction pipeline
5. Validate predictions
6. Generate static site
7. Run tests
8. Deploy to GitHub Pages

### Environment Variables Required
```
# API Keys
GITHUB_TOKEN
SHODAN_API_KEY
VIRUSTOTAL_API_KEY
DEPS_DEV_API_KEY

# Configuration
EPSS_THRESHOLD=0.10
MODEL_VERSION=2.0
PROMETHEUS_GATEWAY
SLACK_WEBHOOK

# Features
ENABLE_EARLY_WARNING=true
ENABLE_CORRELATION_ENGINE=true
```

## External Dependencies

### Python Packages (Main)
- aiohttp==3.10.10 - Async HTTP
- structlog==24.4.0 - Structured logging
- pydantic==2.9.2 - Data validation
- pandas==2.2.3 - Data processing
- scikit-learn==1.5.2 - ML base
- xgboost==2.1.2 - Gradient boosting
- redis==5.1.1 - Caching

### Node.js Packages (Main)
- @11ty/eleventy@3.0.0 - Static site generator
- alpinejs@3.14.3 - Reactive framework
- chart.js@4.4.4 - Charts
- d3@7.9.0 - Advanced visualizations
- fuse.js@7.0.0 - Fuzzy search
- @playwright/test@1.48.2 - E2E testing

### External APIs
- CVE API (cveproject.github.io)
- EPSS Feed (first.org/epss)
- CISA KEV (cisa.gov)
- deps.dev (Google)
- GitHub Advisory Database
- Exploit-DB (optional)

## Security and Compliance

### API Key Management
- Environment variables only
- Never committed to repository
- Secrets in GitHub Actions

### Data Validation Layers
1. Input validation at agent level
2. Schema validation pipeline
3. EPSS threshold enforcement
4. Output verification

### Security Scanning
- Bandit for Python code
- Safety for dependencies
- npm audit for JavaScript
- TruffleHog for secrets

### NIST Compliance Mappings
- **SI-3**: Malicious code protection (CVE filtering)
- **SI-5**: Security alerts and advisories
- **RA-5**: Vulnerability monitoring
- **PM-16**: Threat awareness program

## Monitoring and Metrics

### Logging Infrastructure
- structlog for structured logging
- Log levels: DEBUG, INFO, WARNING, ERROR
- Agent-specific log contexts
- Performance timing logs

### Performance Monitoring
- Prometheus metrics export
- Grafana dashboards
- Agent execution times
- Cache hit rates
- Prediction accuracy tracking

### Accuracy Tracking
- Daily accuracy calculations
- False positive rates
- Model contribution analysis
- Prediction confidence correlation

### Alert Systems
- Slack webhook integration
- High-risk CVE alerts
- Pipeline failure notifications
- Accuracy degradation alerts

## Current State Assessment

### ✅ Fully Implemented
- Project structure and configuration
- Python package setup (pyproject.toml)
- Node.js package setup (package.json)
- Docker compose configuration
- CI/CD workflows (GitHub Actions)
- Environment configuration (.env.example)
- Base documentation files
- Makefile with common commands

### 🟡 Partially Implemented
- Agent implementations (structure exists, code shown in examples)
- ML models (structure exists, code shown in examples)
- Frontend templates (structure exists, code shown in examples)
- Test suites (configured but tests not written)

### ❌ Not Started
- Actual agent code implementations
- ML model training code
- Frontend component implementations
- Test case implementations
- API endpoint handlers
- Monitoring dashboards

### 🔍 Identified Gaps
1. **Code Implementation**: While comprehensive examples were provided, actual code files need to be created
2. **Database Schema**: No database migrations or schema definitions found
3. **API Server**: No FastAPI or Flask server implementation found
4. **Model Training**: Training scripts referenced but not implemented
5. **Test Coverage**: Test infrastructure configured but no actual tests
6. **Documentation**: API docs and deployment guides need creation

## Code Statistics

### File Counts
- Python files: ~49 total (includes examples and empty __init__.py)
- JavaScript files: ~11 (frontend)
- Configuration files: ~10
- Documentation files: ~8

### Component Breakdown
- **Agents**: 10 agent types defined
- **ML Models**: 7 prediction models
- **Frontend Pages**: 5 main templates
- **API Endpoints**: 4 main endpoints planned
- **Workflows**: 2 GitHub Actions

### Test Coverage
- **Current**: 0% (tests not implemented)
- **Target**: 85%+

## Recommendations

1. **Priority 1**: Implement core agent code files
2. **Priority 2**: Create ML model implementations
3. **Priority 3**: Build frontend components
4. **Priority 4**: Write comprehensive test suite
5. **Priority 5**: Set up monitoring infrastructure

The architecture is well-designed with clear separation of concerns, modern technology choices, and comprehensive planning. The implementation phase should focus on translating the documented examples into working code while maintaining the established patterns.