# BlueGuardian AI - Quick Start Guide

Welcome to BlueGuardian AI! This guide will get you up and running in minutes.

## Prerequisites

- Python 3.11 or higher
- Docker (optional, for sandbox execution)
- At least one AI provider API key (Claude or OpenAI recommended)

## Installation

### 1. Setup Environment

```bash
# Navigate to project directory
cd /opt/blue-team-ai

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure API Keys

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your API keys
nano .env  # or use your preferred editor
```

**Minimum configuration:**
```bash
# Required: At least ONE of these
ANTHROPIC_API_KEY=sk-ant-your-key-here
OPENAI_API_KEY=sk-your-key-here

# Optional but recommended
VIRUSTOTAL_API_KEY=your-vt-key-here

# For multi-model consensus (recommended)
ENABLE_MULTI_MODEL_CONSENSUS=true
CONSENSUS_PROVIDERS=claude,openai
```

### 3. Build Docker Sandbox (Optional)

```bash
# Build the sandbox image
docker build -t blueguardian-ai-sandbox:latest .

# Verify image was built
docker images | grep blueguardian
```

## Usage

### Interactive Mode (Recommended for First Use)

```bash
# Start interactive CLI
python -m src.interfaces.cli_interactive interactive
```

**Example Session:**
```
blueguardian> help
Available Commands:
  load <path>      - Load a file for analysis
  analyze          - Analyze loaded file
  export <path>    - Export results to JSON
  status           - Show system status
  help             - Show this help
  exit             - Exit the program

blueguardian> status
┏━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Component          ┃ Status                     ┃
┡━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ AI Providers       │ 2 configured: claude,gpt-4 │
│ Consensus          │ Enabled (2 providers)      │
│ Hallucination Guard│ Enabled                    │
│ Threat Intelligence│ VT: ✓                      │
│ Agents             │ 1 available: malware       │
└────────────────────┴────────────────────────────┘

blueguardian> load /path/to/suspicious.exe
✓ Loaded: suspicious.exe (245,678 bytes)
Path: /path/to/suspicious.exe

blueguardian> analyze

Analyzing: suspicious.exe
...
```

### Command-Line Mode (Batch Analysis)

```bash
# Analyze a single file
python -m src.interfaces.cli_interactive analyze-file suspicious.exe

# Analyze and export report
python -m src.interfaces.cli_interactive analyze-file suspicious.exe --output report.json
```

### Python API

```python
import asyncio
from src.core.orchestrator import Orchestrator
from src.config.settings import get_settings

async def analyze_file():
    # Initialize
    settings = get_settings()
    orchestrator = Orchestrator(settings)

    # Analyze
    result = await orchestrator.analyze_file("suspicious.exe")

    # Print results
    print(f"Verdict: {result.verdict.value}")
    print(f"Confidence: {result.confidence:.0%}")
    print(f"IOCs: {len(result.iocs)}")

    # Export
    with open("report.json", "w") as f:
        json.dump(result.to_dict(), f, indent=2)

    # Cleanup
    await orchestrator.shutdown()

# Run
asyncio.run(analyze_file())
```

## Testing the Setup

### Test 1: Check System Status

```bash
python -m src.interfaces.cli_interactive status
```

Expected output should show:
- ✓ AI providers configured
- ✓ Agents available
- ✓ VirusTotal (if configured)

### Test 2: Analyze EICAR Test File

```bash
# Download EICAR test file (harmless test file)
curl -o eicar.com https://secure.eicar.org/eicar.com

# Analyze it
python -m src.interfaces.cli_interactive analyze-file eicar.com

# Should detect it as malicious (it's designed to trigger AV)
```

### Test 3: Check Costs

After running analyses, you can check API costs:
```python
from src.core.orchestrator import Orchestrator

orchestrator = Orchestrator()
costs = orchestrator.get_costs()
print(f"Total cost: ${costs['total']:.4f}")
```

## Common Issues & Solutions

### Issue: "No AI providers initialized"
**Solution**: Check that API keys are correctly set in `.env` file

### Issue: "pefile not found"
**Solution**:
```bash
pip install pefile pyelftools
```

### Issue: "Cannot connect to Docker"
**Solution**:
- Ensure Docker is installed and running
- Or disable sandbox: `ENABLE_DOCKER_SANDBOX=false` in `.env`

### Issue: "VirusTotal API error"
**Solution**:
- Check API key is valid
- Note: VT has rate limits (4 requests/minute for free tier)

## Next Steps

1. **Explore Features**: Try different file types (.exe, .pdf, .docx)
2. **Customize Agents**: See `docs/AGENT_MODES.md` for creating custom agents
3. **Setup MCP Tools**: Integrate Ghidra, IDA Pro (see `docs/MCP_INTEGRATION.md`)
4. **Configure Web UI**: Enable and configure the React frontend
5. **Add More Providers**: Configure Gemini or Ollama for local models

## Getting Help

- **Documentation**: Check the `docs/` directory
- **Examples**: See `examples/` for code samples
- **Issues**: Report bugs at https://github.com/your-org/blueguardian-ai/issues

## Security Reminders

⚠️ **IMPORTANT**:
- Never analyze actual malware on production systems
- Use Docker sandbox for suspicious files
- Keep API keys secure (never commit .env)
- Review AI outputs carefully - always verify findings

---

**Happy Hunting! 🛡️**
