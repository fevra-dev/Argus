# Contributing to Argus

Thank you for your interest in contributing to Argus! This document provides guidelines and information for contributors.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## How to Contribute

### Reporting Bugs

1. Check existing [Issues](https://github.com/fevra-dev/Argus/issues) to avoid duplicates
2. Create a new issue with:
   - Clear, descriptive title
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version)
   - Relevant logs or error messages

### Suggesting Features

1. Open an issue with the `enhancement` label
2. Describe the feature and its use case
3. Explain why it would benefit the project

### Submitting Code

#### Setup

```bash
# Fork and clone the repository
git clone git@github.com:YOUR_USERNAME/Argus.git
cd Argus

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

#### Development Workflow

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following code style guidelines

3. Write/update tests:
   ```bash
   pytest tests/ -v
   ```

4. Commit with clear messages:
   ```bash
   git commit -m "feat: add new protocol plugin for PostgreSQL"
   ```

5. Push and create a Pull Request

### Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `style:` Code style (formatting, semicolons, etc.)
- `refactor:` Code refactoring
- `test:` Adding/updating tests
- `chore:` Maintenance tasks

### Code Style

- Follow PEP 8 guidelines
- Use type hints where appropriate
- Add docstrings to functions and classes (JSDoc3 style)
- Comment the "why", not the "what"
- Keep functions focused and small

#### Example:

```python
def scan_host(
    host: str,
    ports: List[int],
    timeout: float = 5.0
) -> HostInfo:
    """
    Scan a single host for open ports.
    
    Args:
        host: Target IP address or hostname
        ports: List of ports to scan
        timeout: Connection timeout in seconds
        
    Returns:
        HostInfo object containing scan results
        
    Raises:
        ValueError: If host is invalid
    """
    # Implementation here
```

### Adding Protocol Plugins

To add support for a new protocol:

1. Create a new file in `argus/plugins/`
2. Inherit from `BasePlugin`
3. Implement `test_credential()` method
4. Add default credentials
5. Register in `argus/plugins/__init__.py`
6. Add tests in `tests/test_plugins.py`

See existing plugins (SSH, HTTP, Redis) for reference.

## Pull Request Guidelines

- Keep PRs focused on a single feature/fix
- Update documentation if needed
- Ensure tests pass
- Respond to code review feedback promptly

## Questions?

Open an issue or contact: **fev.dev@proton.me**

---

Thank you for contributing to Argus! 👁️
