# Integration Tests

This directory contains integration tests that test multiple components working together.

## Test Structure

```
test_integration/
├── test_full_analysis_flow.py     # End-to-end analysis flow
├── test_api_integration.py        # API endpoint integration
├── test_threat_intel_integration.py # Threat intel API integration
├── test_siem_integration.py       # SIEM integration tests
└── test_multi_agent_workflow.py   # Multi-agent collaboration
```

## Running Tests

```bash
# Run all integration tests
pytest tests/test_integration/

# Run with slower timeout (integration tests take longer)
pytest tests/test_integration/ --timeout=300

# Skip integration tests (for quick runs)
pytest -m "not integration"
```

## Test Guidelines

1. **External Dependencies**: Mock external APIs (VT, OTX, etc.) to avoid rate limits
2. **Test Data**: Use realistic test data that mimics production scenarios
3. **Cleanup**: Always clean up resources (files, containers) after tests
4. **Isolation**: Each test should be independent and not affect others
5. **Markers**: Use pytest markers to categorize tests

## Example Test

```python
import pytest
from src.core.orchestrator import Orchestrator
from src.config.settings import get_settings

@pytest.mark.integration
@pytest.mark.asyncio
async def test_full_malware_analysis_flow(tmp_path):
    """Test complete malware analysis workflow."""
    # Setup
    settings = get_settings()
    orchestrator = Orchestrator(settings)

    # Create test file
    test_file = tmp_path / "test.exe"
    test_file.write_bytes(b"MZ" + b"\x00" * 100)

    # Run analysis
    result = await orchestrator.analyze_file(str(test_file))

    # Verify
    assert result is not None
    assert result.verdict in ['malicious', 'suspicious', 'clean', 'unknown']
    assert result.confidence > 0
```

## Environment Variables for Tests

```bash
# Set test mode to avoid hitting real APIs
export BLUEGUARDIAN_TEST_MODE=true
export VIRUSTOTAL_API_KEY=test-key
export ANTHROPIC_API_KEY=test-key
```
