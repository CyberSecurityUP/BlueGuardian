# BlueGuardian AI

> Advanced Blue Team Security Analysis Framework powered by Multiple AI Models

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

BlueGuardian AI is a comprehensive security analysis framework designed specifically for **Blue Team** operations, combining the power of multiple AI models (Claude, GPT-4, Gemini, Ollama) with specialized security tools to provide accurate, hallucination-resistant malware analysis, threat intelligence, and incident response capabilities.

## Features

### Core Capabilities

- **Multi-Model AI Integration**: Leverage Claude, GPT-4, Gemini, and local Ollama models
- **Hallucination Prevention**: Multi-model consensus system validates AI outputs
- **Specialized Agents**: Purpose-built agents for different security analysis types
- **MCP Integration**: Native support for security tools via Model Context Protocol
- **Docker Sandbox**: Secure malware execution in isolated containers
- **Threat Intelligence**: Integrated with VirusTotal, MITRE ATT&CK, AlienVault OTX, Hybrid Analysis
- **Multi-Interface**: CLI (interactive & batch), REST API, and Web UI

### Analysis Types

| Agent Type | Capabilities |
|------------|-------------|
| **Malware Agent** | PE/EXE/ELF analysis, packing detection, IOC extraction, behavioral analysis |
| **Document Agent** | PDF, DOCX, XLSX, LNK analysis, macro detection, exploit identification |
| **Phishing Agent** | Email parsing, header analysis, SPF/DKIM validation, brand impersonation detection |
| **Memory Agent** | Volatility 3 integration, process analysis, memory forensics, rootkit detection |
| **Network Agent** | IP/domain reputation, WHOIS, DNS analysis, URL deobfuscation, DGA detection |
| **SIEM Log Agent** | Log analysis, brute force detection, privilege escalation, lateral movement |
| **Incident Response** | Automated IR workflows, timeline reconstruction, evidence collection |

## Quick Start

### Prerequisites

- Python 3.11 or higher
- Docker (optional, for sandbox execution)
- API keys for desired AI providers (Claude, OpenAI, Gemini)

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/blueguardian-ai.git
cd blueguardian-ai

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment variables
cp .env.example .env
# Edit .env with your API keys
```

### Configuration

Edit `.env` file with your configuration:

```bash
# Required: At least one AI provider
ANTHROPIC_API_KEY=sk-ant-your-key-here
OPENAI_API_KEY=sk-your-key-here

# Optional: Threat Intelligence APIs
VIRUSTOTAL_API_KEY=your-vt-key-here
HYBRID_ANALYSIS_API_KEY=your-ha-key-here
OTX_API_KEY=your-otx-key-here

# SIEM Integration (Optional)
ENABLE_SIEM_INTEGRATION=true
SIEM_TYPE=splunk  # splunk, elasticsearch, azure_sentinel, syslog
SPLUNK_HEC_TOKEN=your-token-here
SPLUNK_HEC_URL=https://your-splunk:8088

# Enable multi-model consensus (recommended)
ENABLE_MULTI_MODEL_CONSENSUS=true
CONSENSUS_PROVIDERS=claude,openai
```

## Usage Examples

### CLI Interactive Mode

```bash
# Start interactive CLI
blueguardian

# Or using the short alias
bgai
```

**Example Session:**

```bash
blueguardian> load suspicious_file.exe
[+] Loaded: suspicious_file.exe (PE32, 245KB)
[+] Auto-selected: MalwareAgent (PE mode)

blueguardian> analyze
[*] Running static analysis...
[*] Querying AI models (Claude, GPT-4)...
[*] Computing consensus...
[+] Analysis complete (confidence: 94%)

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Analysis Summary                               ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Verdict: Malicious                             ┃
┃ Confidence: 94%                                ┃
┃ Family: Emotet (probable)                      ┃
┃ MITRE ATT&CK: T1055, T1082, T1012             ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

blueguardian> show iocs
[+] IOCs Identified:
    C2 Servers:
      - 192.168.1.100:4444
      - malicious-domain.com

    Registry Keys:
      - HKCU\Software\Microsoft\Windows\CurrentVersion\Run

    Mutexes:
      - Global\{550E8400-E29B-41D4-A716-446655440000}

blueguardian> export report.json
[+] Report saved: reports/suspicious_file_20251222_143052.json
```

### Python API

```python
from src.core.orchestrator import Orchestrator
from src.config.settings import get_settings

# Initialize
settings = get_settings()
orchestrator = Orchestrator(settings)

# Analyze a file
result = await orchestrator.analyze_file(
    "suspicious.exe",
    agent_type="malware"
)

print(f"Verdict: {result.verdict}")
print(f"Confidence: {result.confidence:.2%}")
print(f"IOCs: {result.iocs}")
```

### REST API

```bash
# Start API server
python -m uvicorn src.interfaces.api_server:app --reload --host 0.0.0.0 --port 8000

# Submit file analysis job
curl -X POST http://localhost:8000/api/v1/analyze/file \
  -F "file=@suspicious.exe" \
  -F "agent_type=malware"

# Analyze URL or IP
curl -X POST http://localhost:8000/api/v1/analyze/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-domain.com", "agent_type": "network"}'

# Check job status
curl http://localhost:8000/api/v1/jobs/{job_id}

# Get analysis result
curl http://localhost:8000/api/v1/jobs/{job_id}/result

# Download report (HTML, PDF, JSON, Markdown)
curl http://localhost:8000/api/v1/jobs/{job_id}/report/html -o report.html

# List all jobs
curl http://localhost:8000/api/v1/jobs

# Get system status
curl http://localhost:8000/api/v1/status

# Get API costs
curl http://localhost:8000/api/v1/costs
```

### Web UI

```bash
# Install frontend dependencies
cd frontend
npm install

# Start development server
npm run dev

# Build for production
npm run build
```

Access the web interface at `http://localhost:3000` with features:
- **Dashboard**: Real-time statistics and charts
- **Analysis**: Drag-and-drop file upload and URL analysis
- **Jobs**: Track and manage all analysis jobs
- **Job Details**: View comprehensive results with IOCs and MITRE ATT&CK techniques
- **Settings**: System configuration and cost tracking
- **Report Export**: Download reports in HTML, PDF, or JSON

### CLI Batch Mode

```bash
# Analyze multiple files
python -m src.interfaces.cli_batch analyze file1.exe file2.pdf file3.lnk -o reports/

# Scan entire directory
python -m src.interfaces.cli_batch scan-directory /path/to/samples --recursive -f html

# Generate reports in different formats
python -m src.interfaces.cli_batch analyze suspicious.exe --format pdf --output reports/
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     User Interfaces                         │
│  ┌──────────┐    ┌──────────┐    ┌──────────────────────┐  │
│  │   CLI    │    │ REST API │    │      Web UI          │  │
│  └─────┬────┘    └────┬─────┘    └──────────┬───────────┘  │
└────────┼──────────────┼───────────────────────┼──────────────┘
         │              │                       │
         └──────────────┼───────────────────────┘
                        │
         ┌──────────────▼─────────────────┐
         │      Orchestrator              │
         │  (Coordinates analysis flow)   │
         └──────────────┬─────────────────┘
                        │
         ┌──────────────▼─────────────────┐
         │   Hallucination Guard          │
         │  (Multi-model consensus)       │
         └──────────┬──────────┬──────────┘
                    │          │
        ┌───────────▼──┐   ┌──▼────────────┐
        │ AI Providers │   │ Agents        │
        │ - Claude     │   │ - Malware     │
        │ - OpenAI     │   │ - Phishing    │
        │ - Gemini     │   │ - Forensics   │
        │ - Ollama     │   │ - Document    │
        └──────────────┘   └───┬───────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
        ┌─────▼──────┐  ┌─────▼──────┐  ┌─────▼──────┐
        │ Analyzers  │  │    MCP     │  │  Threat    │
        │ - PE/ELF   │  │  Tools     │  │  Intel     │
        │ - PDF/Doc  │  │ - Ghidra   │  │ - VT       │
        │ - Email    │  │ - IDA      │  │ - MITRE    │
        │ - Memory   │  │ - Vol      │  │ - OTX      │
        └────────────┘  └────────────┘  └────────────┘
```

## Anti-Hallucination System

BlueGuardian AI implements a sophisticated multi-model consensus mechanism:

1. **Parallel Querying**: Sends queries to multiple AI models simultaneously
2. **Claim Extraction**: Breaks down responses into individual assertions
3. **Similarity Analysis**: Identifies agreements and contradictions
4. **Confidence Scoring**: Calculates reliability based on consensus
5. **Disagreement Flagging**: Highlights areas where models disagree
6. **Tool Validation**: Cross-references AI claims against actual tool outputs

**Example:**

```
Query: "Analyze this suspicious email"

┌─────────────┬──────────────────────────────────────┐
│ Provider    │ Claim                                │
├─────────────┼──────────────────────────────────────┤
│ Claude      │ "Sender domain recently registered"  │ ✓ Agreement (3/3)
│ GPT-4       │ "Domain created 2 days ago"          │ ✓
│ Gemini      │ "New domain, suspicious"             │ ✓
├─────────────┼──────────────────────────────────────┤
│ Claude      │ "Contains macro payload"             │ ✓ Agreement (2/3)
│ GPT-4       │ "Embedded malicious macro"           │ ✓
│ Gemini      │ "No macros detected"                 │ ✗ Disagreement!
└─────────────┴──────────────────────────────────────┘

Confidence Score: 85% (high agreement with 1 flagged inconsistency)
```

## Plugin System

Create custom agents and tools:

```python
# examples/custom_agent_example.py
from src.agents.base_agent import BaseAgent

class CustomThreatHuntAgent(BaseAgent):
    """Custom threat hunting agent."""

    async def analyze(self, artifact_path):
        # Your custom analysis logic
        results = await self.run_custom_tools(artifact_path)

        # Query AI with specialized prompt
        response = await self.ai_query(
            prompt=self.prompts.threat_hunting,
            context=results
        )

        return response

# Register the agent
from src.core.agent_manager import register_agent
register_agent("threat_hunt", CustomThreatHuntAgent)
```

## Docker Sandbox

Safely execute suspicious files in isolated containers:

```bash
# Build sandbox image
docker build -t blueguardian-ai-sandbox:latest -f Dockerfile .

# Analysis automatically uses sandbox when enabled
blueguardian> analyze --sandbox suspicious.exe
```

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test suite
pytest tests/test_agents/
```

### Code Quality

```bash
# Format code
black src/ tests/

# Lint
ruff check src/ tests/

# Type checking
mypy src/
```

### Project Structure

```
blueguardian-ai/
├── src/
│   ├── core/              # Core orchestration logic
│   ├── ai_providers/      # AI model integrations
│   ├── agents/            # Specialized analysis agents
│   ├── analyzers/         # Tool-specific analyzers
│   ├── integrations/      # Threat intel integrations
│   ├── mcp/               # Model Context Protocol
│   ├── prompts/           # Specialized prompts
│   ├── utils/             # Utilities (sandbox, IOC extraction)
│   └── interfaces/        # CLI, API, Web UI
├── tests/                 # Test suites
├── docs/                  # Documentation
├── data/                  # YARA rules, signatures
└── examples/              # Usage examples
```

## Roadmap

### Phase 1: Core MVP ✅ COMPLETED
- [x] Multi-AI provider abstraction (Claude, OpenAI, Gemini, Ollama)
- [x] Hallucination prevention via multi-model consensus
- [x] Configuration management with Pydantic
- [x] Base agent framework
- [x] Malware agent (PE/ELF analysis)
- [x] CLI interactive interface
- [x] Docker sandbox system
- [x] VirusTotal integration
- [x] MITRE ATT&CK framework integration

### Phase 2: Document & Email Analysis ✅ COMPLETED
- [x] Document analysis agent (PDF, DOCX, XLSX, LNK)
- [x] Phishing detection agent (email parsing, SPF/DKIM)
- [x] PDF analyzer (JavaScript/exploit detection)
- [x] Office analyzer (macro/DDE detection)
- [x] Email analyzer (header validation, brand impersonation)
- [x] LNK analyzer (PowerShell detection)
- [x] Plugin system foundation

### Phase 3: Advanced Tools & SIEM ✅ COMPLETED
- [x] Memory forensics agent (Volatility 3 integration)
- [x] Network analysis agent (IP/domain/URL)
- [x] JavaScript deobfuscator (multi-layer)
- [x] Auto-tool installation system
- [x] Hybrid Analysis API integration
- [x] AlienVault OTX integration
- [x] **SIEM integration** (Splunk, ELK, Azure Sentinel, Syslog)
- [x] **SIEM log analysis agent**

### Phase 4: Interfaces & Reporting ✅ COMPLETED
- [x] REST API (FastAPI with 11 endpoints)
- [x] CLI batch mode (multi-file processing)
- [x] Report generation (JSON, HTML, Markdown, PDF)
- [x] Web UI (React + TypeScript)
  - [x] Dashboard with charts and statistics
  - [x] File upload and URL analysis
  - [x] Jobs listing and filtering
  - [x] Detailed results viewer with IOCs
  - [x] Settings and cost tracking

### Phase 5: Extensibility 🚧 PLANNED
- [ ] GitHub plugin support (load plugins from repos)
- [ ] Custom agent YAML/JSON configuration
- [ ] Community plugin marketplace
- [ ] MITRE ATT&CK Navigator visualization
- [ ] Advanced reporting templates
- [ ] Integration with more SIEM platforms
- [ ] Collaborative analysis features
- [ ] API rate limiting and authentication
- [ ] Advanced caching strategies

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

## Security

**IMPORTANT**: This tool analyzes potentially malicious content. Always:
- Run in isolated environments
- Use Docker sandbox for dynamic analysis
- Never analyze unknown files on production systems
- Keep API keys secure (use `.env`, never commit)

For security issues, please email security@blueguardian-ai.example

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- Built with [Anthropic Claude](https://anthropic.com/), [OpenAI GPT](https://openai.com/), [Google Gemini](https://deepmind.google/technologies/gemini/)
- MITRE ATT&CK framework
- VirusTotal, Hybrid Analysis, AlienVault OTX APIs
- Open source security tools: YARA, Volatility, Ghidra, IDA, Radare2

## Support

- Documentation: https://blueguardian-ai.readthedocs.io
- Issues: https://github.com/your-org/blueguardian-ai/issues
- Discussions: https://github.com/your-org/blueguardian-ai/discussions

---

**Made with ❤️ for the Blue Team community**
>>>>>>> 8ac350f (Initial commit)
