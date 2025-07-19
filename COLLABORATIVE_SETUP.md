# Network Intelligence - Collaborative Development Setup

This guide provides complete instructions for setting up the Network Intelligence suite for collaborative development.

## 🚀 Quick Start

### Option 1: Automated Setup (Recommended)
```bash
# Run the automated setup script
./create_github_repos.sh
```

### Option 2: Manual Setup
Follow the step-by-step instructions below.

## 📋 Prerequisites

- GitHub account with SSH key configured
- Heroku CLI installed and authenticated
- Python 3.11+ installed
- Git installed

## 🔧 Step-by-Step Setup

### 1. Create GitHub Repositories

Visit https://github.com/new for each repository:

#### Development Repository
- **Name**: `network-intelligence-dev`
- **Description**: `Network Intelligence Development App`
- **Visibility**: Public (or Private)
- **Initialize**: ❌ Don't initialize with README

#### Staging Repository
- **Name**: `network-intelligence-stage`
- **Description**: `Network Intelligence Staging App`
- **Visibility**: Public (or Private)
- **Initialize**: ❌ Don't initialize with README

#### Production Repository
- **Name**: `network-intelligence-prod`
- **Description**: `Network Intelligence Production App`
- **Visibility**: Public (or Private)
- **Initialize**: ❌ Don't initialize with README

### 2. Push Code to GitHub

For each repository, run these commands in the respective local directory:

#### Development
```bash
cd /Users/brust/bin/network-intelligence-dev
git remote add origin https://github.com/benjaminrust/network-intelligence-dev.git
git push -u origin main
```

#### Staging
```bash
cd /Users/brust/bin/network-intelligence-stage
git remote add origin https://github.com/benjaminrust/network-intelligence-stage.git
git push -u origin main
```

#### Production
```bash
cd /Users/brust/bin/network-intelligence-prod
git remote add origin https://github.com/benjaminrust/network-intelligence-prod.git
git push -u origin main
```

## 🔐 GitHub Repository Configuration

### 3. Set Up Branch Protection Rules

For each repository, go to Settings → Branches and add protection rules:

#### Main Branch Protection
- ✅ **Require a pull request before merging**
- ✅ **Require approvals** (at least 1)
- ✅ **Dismiss stale PR approvals when new commits are pushed**
- ✅ **Require status checks to pass before merging**
- ✅ **Require branches to be up to date before merging**
- ✅ **Include administrators**

### 4. Configure GitHub Secrets

For each repository, go to Settings → Secrets and variables → Actions and add:

#### Required Secrets
- `HEROKU_API_KEY` - Your Heroku API key
- `HEROKU_EMAIL` - Your Heroku email
- `HEROKU_PIPELINE_ID` - Network Intelligence pipeline ID

#### Optional Secrets
- `CODECOV_TOKEN` - For code coverage reporting
- `SLACK_WEBHOOK_URL` - For Slack notifications

### 5. Set Up Issue Templates

The following templates are already included:
- Bug Report Template
- Feature Request Template

### 6. Configure Project Settings

#### Repository Settings
- Enable Issues
- Enable Projects
- Enable Wiki (optional)
- Enable Discussions (optional)

#### Collaborator Access
- Add team members as collaborators
- Set appropriate permission levels:
  - **Read**: View and comment
  - **Write**: Push code and create issues
  - **Admin**: Full access

## 🔄 CI/CD Pipeline Configuration

### 7. GitHub Actions Setup

The CI/CD workflow is already configured in `.github/workflows/ci.yml`:

#### What it does:
- ✅ **Testing**: Runs unit tests with pytest
- ✅ **Linting**: Code quality checks with flake8
- ✅ **Security**: Security scans with Bandit and Safety
- ✅ **Deployment**: Automatic deployment to Heroku
- ✅ **Pipeline Promotion**: Automatic promotion through environments

#### Workflow Triggers:
- Push to `main` branch
- Pull requests to `main` branch
- Push to `develop` branch

### 8. Heroku Pipeline Integration

The Heroku pipeline is already configured:
```
Development → Staging → Production
```

#### Manual Promotion Commands:
```bash
# Dev to Staging
heroku pipelines:promote -a network-intelligence-dev -to network-intelligence-stage

# Staging to Production
heroku pipelines:promote -a network-intelligence-stage -to network-intelligence-prod
```

## 👥 Team Collaboration Setup

### 9. Add Team Members

#### GitHub Teams
1. Create a team in your GitHub organization
2. Add team members
3. Grant appropriate repository access

#### Heroku Access
1. Add team members as collaborators to Heroku apps
2. Grant appropriate permissions

### 10. Communication Channels

#### Recommended Tools:
- **Slack**: For real-time communication
- **GitHub Discussions**: For project discussions
- **GitHub Issues**: For bug tracking and feature requests
- **GitHub Projects**: For project management

## 📊 Monitoring and Analytics

### 11. Set Up Monitoring

#### Recommended Add-ons:
- **Heroku Add-ons**:
  - Papertrail (logging)
  - New Relic (performance monitoring)
  - Scout (application monitoring)

#### GitHub Insights:
- Enable repository insights
- Set up dependency alerts
- Configure security advisories

### 12. Code Quality Tools

#### Pre-commit Hooks
```bash
# Install pre-commit
pip install pre-commit

# Set up hooks
pre-commit install
```

#### Code Coverage
- Configure Codecov integration
- Set minimum coverage thresholds
- Enable coverage reporting in CI

## 🚨 Security Setup

### 13. Security Best Practices

#### Repository Security:
- Enable dependency scanning
- Enable secret scanning
- Configure security advisories
- Set up automated security updates

#### Access Control:
- Use SSH keys for Git access
- Enable two-factor authentication
- Regular access reviews
- Principle of least privilege

### 14. Environment Security

#### Heroku Security:
- Use environment variables for secrets
- Enable Heroku Shield (if needed)
- Configure SSL/TLS
- Regular security audits

## 📈 Performance and Scaling

### 15. Performance Monitoring

#### Metrics to Track:
- Response times
- Error rates
- Resource utilization
- Database performance

#### Scaling Strategy:
- Auto-scaling configuration
- Load balancing
- Database optimization
- Caching strategies

## ✅ Verification Checklist

After setup, verify:

- [ ] All three GitHub repositories created
- [ ] Code pushed to all repositories
- [ ] Branch protection rules configured
- [ ] GitHub Actions workflows working
- [ ] Heroku pipeline connected
- [ ] Team members added
- [ ] Monitoring tools configured
- [ ] Security measures in place
- [ ] Documentation complete
- [ ] Testing pipeline functional

## 🆘 Troubleshooting

### Common Issues:

#### GitHub Issues:
- **Permission denied**: Check SSH key configuration
- **Repository not found**: Verify repository name and access
- **Branch protection conflicts**: Check protection rule settings

#### Heroku Issues:
- **Deployment failed**: Check build logs and requirements
- **Pipeline promotion failed**: Verify app names and permissions
- **Environment variables missing**: Check Heroku config vars

#### CI/CD Issues:
- **Workflow not triggering**: Check branch names and triggers
- **Tests failing**: Review test output and fix issues
- **Deployment timeout**: Check Heroku app status

## 📞 Support

For issues or questions:
1. Check the troubleshooting section
2. Review GitHub and Heroku documentation
3. Create an issue in the appropriate repository
4. Contact the project maintainers

---

**🎉 Congratulations!** Your Network Intelligence suite is now ready for collaborative development! 