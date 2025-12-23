# Analyzer Tests

This directory contains unit tests for all file analyzers.

## Test Structure

```
test_analyzers/
├── test_pe_analyzer.py          # Tests for PE/EXE analyzer
├── test_elf_analyzer.py         # Tests for ELF analyzer
├── test_pdf_analyzer.py         # Tests for PDF analyzer
├── test_office_analyzer.py      # Tests for Office document analyzer
├── test_lnk_analyzer.py         # Tests for LNK shortcut analyzer
├── test_email_analyzer.py       # Tests for email analyzer
├── test_memory_analyzer.py      # Tests for memory dump analyzer
├── test_network_analyzer.py     # Tests for network indicator analyzer
└── test_js_deobfuscator.py      # Tests for JavaScript deobfuscator
```

## Running Tests

```bash
# Run all analyzer tests
pytest tests/test_analyzers/

# Run specific analyzer test
pytest tests/test_analyzers/test_pe_analyzer.py

# Run with verbose output
pytest tests/test_analyzers/ -v
```

## Test Guidelines

1. **Real Samples**: Use actual file samples (safe ones) for testing
2. **Edge Cases**: Test malformed files, encrypted files, empty files
3. **Performance**: Test analyzer performance with large files
4. **Error Handling**: Verify proper error handling for corrupt files
5. **IOC Extraction**: Verify correct extraction of IOCs

## Example Test

```python
import pytest
from src.analyzers.pe_analyzer import PEAnalyzer

def test_pe_analyzer_basic_info(sample_pe_executable):
    """Test PE analyzer extracts basic information."""
    analyzer = PEAnalyzer()
    result = analyzer.analyze(sample_pe_executable)

    assert result.file_type == 'PE32'
    assert result.architecture in ['x86', 'x64']
    assert len(result.sections) > 0
    assert len(result.imports) > 0
```
