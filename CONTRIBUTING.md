# Contributing to NOPE

🐙 Thank you for your interest in contributing to NOPE! We welcome contributions that help predict and prevent exploitation of vulnerabilities.

## Code of Conduct

Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project you agree to abide by its terms.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- A clear and descriptive title
- Steps to reproduce the issue
- Expected behavior vs actual behavior
- Screenshots if applicable
- Your environment details (OS, Python version, etc.)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- A clear and descriptive title
- A detailed description of the proposed enhancement
- Any relevant examples or mockups
- Why this enhancement would be useful

### Pull Requests

1. Fork the repo and create your branch from `main`
2. If you've added code that should be tested, add tests
3. Ensure the test suite passes: `make test`
4. Make sure your code follows our style guidelines: `make lint`
5. Issue the pull request!

## Development Setup

```bash
# Clone your fork
git clone https://github.com/your-username/NOPE.git
cd NOPE

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
make install

# Run development server
make dev
```

## Project Structure

```
NOPE/
├── src/           # Python source code
│   ├── agents/    # Agent implementations
│   ├── ml/        # Machine learning models
│   └── utils/     # Utility functions
├── site/          # Frontend code
├── tests/         # Test suite
└── scripts/       # Build and utility scripts
```

## Coding Standards

### Python
- Follow PEP 8
- Use type hints for all functions
- Write docstrings for all public functions
- Maintain 85%+ test coverage

### JavaScript
- Follow Google JavaScript Style Guide
- Use ESLint configuration provided
- Write JSDoc comments

### Commits
- Use clear, descriptive commit messages
- Reference issues and pull requests
- Keep commits atomic and focused

## Testing

### Running Tests

```bash
# Python tests
pytest tests/ -v

# JavaScript tests
npm test

# Full test suite
make test
```

### Writing Tests

- Write unit tests for all new functionality
- Include integration tests for agent interactions
- Add E2E tests for user-facing features
- Test edge cases and error conditions

## Documentation

- Update README.md if needed
- Add docstrings to new functions
- Update architecture docs for significant changes
- Include examples for new features

## Areas We Need Help

### High Priority
- Additional ML models for prediction
- New threat intelligence sources
- Performance optimizations
- Security vulnerability fixes

### Good First Issues
- Documentation improvements
- Test coverage expansion
- UI/UX enhancements
- Bug fixes labeled "good first issue"

### Feature Requests
- Real-time threat correlation
- Additional export formats
- API client libraries
- Visualization improvements

## Release Process

1. Ensure all tests pass
2. Update version in `pyproject.toml` and `package.json`
3. Update CHANGELOG.md
4. Create a pull request
5. After merge, tag the release

## Questions?

Feel free to:
- Open an issue for questions
- Join our discussions
- Contact maintainers

## Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation

Thank you for helping make NOPE better at predicting tomorrow's exploits today! 🐙