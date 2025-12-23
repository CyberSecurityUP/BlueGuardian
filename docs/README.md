# BlueGuardian AI Documentation

Welcome to the BlueGuardian AI documentation directory.

## Documentation Structure

```
docs/
├── architecture/           # System architecture documentation
│   ├── overview.md
│   ├── agent-system.md
│   └── ai-providers.md
├── guides/                # User guides and tutorials
│   ├── getting-started.md
│   ├── api-guide.md
│   ├── web-ui-guide.md
│   └── cli-guide.md
├── development/           # Developer documentation
│   ├── contributing.md
│   ├── plugin-development.md
│   ├── custom-agents.md
│   └── testing.md
├── deployment/            # Deployment guides
│   ├── docker.md
│   ├── kubernetes.md
│   ├── production.md
│   └── security.md
├── api/                   # API documentation
│   ├── rest-api.md
│   ├── websocket.md
│   └── authentication.md
└── troubleshooting/       # Troubleshooting guides
    ├── common-issues.md
    ├── performance.md
    └── debugging.md
```

## Quick Links

### For Users
- [Getting Started](guides/getting-started.md) - Quick start guide
- [Web UI Guide](guides/web-ui-guide.md) - Using the web interface
- [API Guide](guides/api-guide.md) - REST API documentation
- [CLI Guide](guides/cli-guide.md) - Command-line interface

### For Developers
- [Contributing](development/contributing.md) - How to contribute
- [Plugin Development](development/plugin-development.md) - Creating custom plugins
- [Custom Agents](development/custom-agents.md) - Building custom analysis agents
- [Architecture Overview](architecture/overview.md) - System architecture

### For DevOps
- [Docker Deployment](deployment/docker.md) - Deploy with Docker
- [Kubernetes](deployment/kubernetes.md) - Deploy on Kubernetes
- [Production Guide](deployment/production.md) - Production best practices
- [Security Hardening](deployment/security.md) - Security configuration

## Building Documentation

Documentation can be built using various tools:

### Markdown (Recommended)
Documentation is written in Markdown for easy reading on GitHub.

### Sphinx (Optional)
```bash
# Install Sphinx
pip install sphinx sphinx-rtd-theme

# Build HTML docs
cd docs
sphinx-build -b html . _build/html
```

### MkDocs (Optional)
```bash
# Install MkDocs
pip install mkdocs mkdocs-material

# Serve locally
mkdocs serve

# Build static site
mkdocs build
```

## Contributing to Documentation

1. **Follow Markdown style**: Use standard Markdown syntax
2. **Add examples**: Include code examples and screenshots
3. **Keep updated**: Update docs when features change
4. **Link properly**: Use relative links between documents
5. **Test links**: Ensure all links work

## Documentation Standards

### Markdown Format
```markdown
# Title (H1)

Brief introduction paragraph.

## Section (H2)

Content here.

### Subsection (H3)

More specific content.

## Code Examples

\`\`\`python
# Example code
from blueguardian import Analyzer
\`\`\`

## Tables

| Column 1 | Column 2 |
|----------|----------|
| Data 1   | Data 2   |
```

### Screenshots
- Store in `docs/images/`
- Use descriptive filenames
- Optimize file size
- Use PNG for UI screenshots

### Code Examples
- Include working, tested code
- Add comments explaining key parts
- Show both input and output
- Include error handling

## Versioning

Documentation is versioned alongside code:
- `docs/v1.0/` - Version 1.0 docs
- `docs/v2.0/` - Version 2.0 docs
- `docs/latest/` - Latest version (symlink)

## Online Documentation

Documentation is also available online:
- GitHub: https://github.com/your-org/blueguardian-ai/tree/main/docs
- Read the Docs: https://blueguardian-ai.readthedocs.io
- Wiki: https://github.com/your-org/blueguardian-ai/wiki

## Getting Help

- Check [Troubleshooting](troubleshooting/common-issues.md)
- Read [FAQ](FAQ.md)
- Ask on [GitHub Discussions](https://github.com/your-org/blueguardian-ai/discussions)
- Report bugs on [GitHub Issues](https://github.com/your-org/blueguardian-ai/issues)

## License

Documentation is licensed under [Creative Commons Attribution 4.0](https://creativecommons.org/licenses/by/4.0/).

Code examples in documentation are licensed under MIT License (same as the project).
