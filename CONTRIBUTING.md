# Contributing to TZDC

Thank you for your interest in contributing to TZDC! We welcome contributions from the community.

## Getting Started

### Development Setup

1. **Fork and clone the repository**

   ```bash
   git clone https://github.com/jayeshthk/TZDC.git
   cd TZDC
   ```

2. **Create a virtual environment**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install development dependencies**

   ```bash
   pip install -e ".[dev]"
   ```

4. **Install pre-commit hooks**
   ```bash
   pre-commit install
   ```

## How to Contribute

### Reporting Bugs

- Use the [GitHub issue tracker](https://github.com/jayeshthk/TZDC.git/issues)
- Include Python version, TZDC version, and OS
- Provide a minimal reproducible example
- Describe expected vs actual behavior

### Suggesting Features

- Open an issue with the `enhancement` label
- Clearly describe the use case and benefits
- Consider if it fits the project scope

### Code Contributions

1. **Create a new branch**

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**

   - Follow the code style (enforced by Black and Ruff)
   - Add tests for new functionality
   - Update documentation as needed

3. **Run tests**

   ```bash
   pytest
   pytest --cov=tzdc --cov-report=html
   ```

4. **Run code quality checks**

   ```bash
   black src/ tests/
   ruff check src/ tests/
   mypy src/
   ```

5. **Commit your changes**

   ```bash
   git add .
   git commit -m "Add: brief description of changes"
   ```

   Use conventional commit messages:

   - `Add:` for new features
   - `Fix:` for bug fixes
   - `Docs:` for documentation
   - `Test:` for tests
   - `Refactor:` for code refactoring

6. **Push and create a pull request**
   ```bash
   git push origin feature/your-feature-name
   ```

## Code Style

- **Python 3.10+** syntax
- **PEP 8** compliance (enforced by Black)
- **Type hints** for all functions
- **Google-style docstrings**

Example:

```python
def encrypt_data(
    data: bytes,
    key: bytes,
    context: str = "default"
) -> Tuple[bytes, bytes]:
    """
    Encrypt data with temporal key.

    Args:
        data: Raw data to encrypt
        key: 32-byte encryption key
        context: Context for key derivation

    Returns:
        Tuple of (ciphertext, nonce)

    Raises:
        EncryptionError: If encryption fails
    """
    # Implementation
    pass
```

## Testing Guidelines

- Write tests for all new features
- Maintain >90% code coverage
- Use descriptive test names
- Include edge cases and error conditions

Example:

```python
def test_temporal_key_expiration():
    """Test that keys expire correctly after time window."""
    client = TZDCClient(time_window=1)
    # Test implementation
    pass
```

## Documentation

- Update README.md for user-facing changes
- Add docstrings to new functions/classes
- Update API documentation if needed
- Include code examples for new features

## Security

- **Never commit secrets or keys**
- Report security vulnerabilities privately to security@tzdc.io
- Do not open public issues for security problems
- Follow responsible disclosure practices

## Pull Request Process

1. Ensure all tests pass
2. Update documentation
3. Add entry to CHANGELOG.md
4. Request review from maintainers
5. Address review feedback
6. Squash commits if requested

### PR Checklist

- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] No security vulnerabilities introduced

## Community Guidelines

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md)

## Questions?

- **Discussions**: [GitHub Discussions](https://github.com/jayeshthk/TZDC.git/discussions)
- **Email**: jayesh@arkvien.com

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to TZDC!** 🎉
