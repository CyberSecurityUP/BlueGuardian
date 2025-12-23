# Agent Tests

This directory contains unit tests for all BlueGuardian AI agents.

## Test Structure

```
test_agents/
├── test_malware_agent.py      # Tests for malware analysis agent
├── test_document_agent.py     # Tests for document analysis agent
├── test_phishing_agent.py     # Tests for phishing detection agent
├── test_memory_agent.py       # Tests for memory forensics agent
├── test_network_agent.py      # Tests for network analysis agent
└── test_siem_log_agent.py     # Tests for SIEM log analysis agent
```

## Running Tests

```bash
# Run all agent tests
pytest tests/test_agents/

# Run specific agent test
pytest tests/test_agents/test_malware_agent.py

# Run with coverage
pytest tests/test_agents/ --cov=src/agents --cov-report=html
```

## Test Guidelines

1. **Mock AI Providers**: Always mock AI provider responses to avoid API costs
2. **Use Fixtures**: Create reusable fixtures for common test data
3. **Test Edge Cases**: Test error handling, empty inputs, malformed data
4. **Async Tests**: Use `pytest-asyncio` for async agent methods
5. **Sample Files**: Store test samples in `tests/fixtures/`

## Example Test

```python
import pytest
from src.agents.malware_agent import MalwareAgent
from src.config.settings import get_settings

@pytest.mark.asyncio
async def test_malware_agent_pe_analysis(mock_ai_provider, sample_pe_file):
    """Test malware agent PE file analysis."""
    settings = get_settings()
    agent = MalwareAgent(
        settings=settings,
        ai_providers={'claude': mock_ai_provider},
    )

    result = await agent.analyze(sample_pe_file)

    assert result.verdict in ['malicious', 'suspicious', 'clean', 'unknown']
    assert 0 <= result.confidence <= 1
    assert len(result.iocs) >= 0
```
