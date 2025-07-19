# Contributing to Network Intelligence

Thank you for your interest in contributing to the Network Intelligence project! This document provides guidelines for contributing to the project.

## Development Environment

The Network Intelligence suite consists of three environments:
- **Development** (`network-intelligence-dev`) - For active development and testing
- **Staging** (`network-intelligence-stage`) - For pre-production testing
- **Production** (`network-intelligence-prod`) - Live production environment

## Getting Started

### Prerequisites
- Python 3.11+
- Git
- Heroku CLI
- Access to the Network Intelligence Heroku pipeline

### Local Setup
1. Clone the repository you want to work on:
   ```bash
   git clone https://github.com/benjaminrust/network-intelligence-dev.git
   cd network-intelligence-dev
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up environment variables:
   ```bash
   export FLASK_APP=app.py
   export FLASK_ENV=development
   export SECRET_KEY=your-secret-key
   ```

4. Run the application:
   ```bash
   flask run
   ```

## Development Workflow

### 1. Create a Feature Branch
```bash
git checkout -b feature/your-feature-name
```

### 2. Make Your Changes
- Write clean, well-documented code
- Follow the existing code style
- Add tests for new functionality
- Update documentation as needed

### 3. Test Your Changes
```bash
# Run tests (when available)
python -m pytest

# Test locally
flask run
```

### 4. Commit Your Changes
```bash
git add .
git commit -m "feat: add your feature description"
```

### 5. Push and Create Pull Request
```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

## Code Style Guidelines

### Python
- Follow PEP 8 style guidelines
- Use meaningful variable and function names
- Add docstrings to functions and classes
- Keep functions small and focused

### Commit Messages
Use conventional commit format:
- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation changes
- `style:` for formatting changes
- `refactor:` for code refactoring
- `test:` for adding tests
- `chore:` for maintenance tasks

### Example
```
feat: add network traffic monitoring endpoint

- Add /api/traffic endpoint for monitoring network traffic
- Implement traffic analysis algorithms
- Add unit tests for new functionality
```

## Pull Request Process

1. **Create a Pull Request** from your feature branch to `main`
2. **Add a description** explaining your changes
3. **Link related issues** using keywords like "Fixes #123" or "Closes #456"
4. **Request review** from team members
5. **Address feedback** and make necessary changes
6. **Merge** once approved

## Deployment Process

### Development → Staging
```bash
# Promote from development to staging
heroku pipelines:promote -a network-intelligence-dev -to network-intelligence-stage
```

### Staging → Production
```bash
# Promote from staging to production
heroku pipelines:promote -a network-intelligence-stage -to network-intelligence-prod
```

## Testing

### Unit Tests
- Write unit tests for new functionality
- Ensure all tests pass before submitting PR
- Aim for good test coverage

### Integration Tests
- Test API endpoints
- Verify database operations
- Check external service integrations

### Manual Testing
- Test in development environment
- Verify functionality in staging before production deployment

## Security

- Never commit sensitive information (API keys, passwords, etc.)
- Use environment variables for configuration
- Follow security best practices
- Report security vulnerabilities privately

## Documentation

- Update README.md for significant changes
- Add inline comments for complex logic
- Document API endpoints
- Keep setup instructions current

## Getting Help

- Create an issue for bugs or feature requests
- Ask questions in the project discussions
- Review existing issues and pull requests

## Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Help others learn and grow
- Follow the project's code of conduct

Thank you for contributing to Network Intelligence! 