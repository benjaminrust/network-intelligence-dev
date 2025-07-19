# 🛡️ Network Intelligence Platform

> **⚠️ DISCLAIMER: This is a proof of concept project for demonstration purposes only. Not intended for production use without proper security review and hardening.**

[![Heroku](https://img.shields.io/badge/Heroku-430098?style=for-the-badge&logo=heroku&logoColor=white)](https://heroku.com)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)](https://postgresql.org)
[![Redis](https://img.shields.io/badge/Redis-DC382D?style=for-the-badge&logo=redis&logoColor=white)](https://redis.io)
[![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)

## 🎯 Overview

A comprehensive **Network Intelligence Platform** that provides real-time security monitoring, threat detection, and network analytics. Built with modern technologies for enterprise-grade security operations.

## ✨ Features

### 🔍 **Real-time Network Monitoring**
- **Traffic Analysis**: Advanced pattern detection and risk scoring
- **Threat Intelligence**: Integration with threat feeds and indicators
- **Security Events**: Comprehensive event logging and correlation
- **Live Dashboard**: Real-time visualization of network status

### 🗄️ **Data Management**
- **PostgreSQL Database**: Persistent storage for events, analytics, and intelligence
- **Redis Caching**: High-performance caching for real-time data
- **Session Management**: User session tracking and security
- **Analytics Engine**: Network metrics and performance monitoring

### 🛡️ **Security Features**
- **Threat Detection**: AI-powered threat identification
- **Risk Scoring**: Dynamic risk assessment algorithms
- **Alert Management**: Intelligent alert generation and escalation
- **Geolocation**: IP-based location tracking and analysis

### 📊 **Analytics & Reporting**
- **Network Analytics**: Real-time metrics and performance data
- **Security Metrics**: Threat intelligence and risk assessments
- **Cache Statistics**: Redis performance monitoring
- **Custom Dashboards**: Configurable visualization panels

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Dashboard │    │   API Gateway   │    │  Background     │
│   (Frontend)    │◄──►│   (Flask App)   │◄──►│  Monitor        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   PostgreSQL    │    │     Redis       │    │  Threat Intel   │
│   (Database)    │◄──►│   (Cache)       │◄──►│  (AI Models)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- PostgreSQL 13+
- Redis 6+
- Heroku CLI (for deployment)

### Local Development

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd network-intelligence-dev
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**
   ```bash
   export DATABASE_URL="postgresql://user:pass@localhost:5432/network_intel"
   export REDIS_URL="redis://localhost:6379"
   export SECRET_KEY="your-secret-key-here"
   ```

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Access the dashboard**
   ```
   http://localhost:5000
   ```

## 📡 API Endpoints

### Health & Status
- `GET /api/health` - System health check
- `GET /api/network/status` - Network status overview

### Traffic Analysis
- `POST /api/network/analyze` - Analyze network traffic
- `GET /api/events` - Get security events
- `POST /api/events` - Create security event

### Threat Intelligence
- `GET /api/threats/indicators` - Get threat indicators
- `POST /api/threats/indicators` - Add threat indicator

### Alerts & Monitoring
- `GET /api/alerts` - Get security alerts
- `PUT /api/alerts/{id}` - Update alert status

### Analytics
- `GET /api/analytics/metrics` - Get network metrics
- `POST /api/analytics/metrics` - Record metric

### Session Management
- `POST /api/sessions` - Create user session
- `GET /api/sessions/{id}` - Get session data

### Cache Management
- `GET /api/cache/stats` - Get cache statistics
- `POST /api/cache/clear` - Clear cache

## 🗄️ Database Schema

### Security Events
```sql
CREATE TABLE security_events (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    source_ip INET,
    destination_ip INET,
    risk_score INTEGER DEFAULT 0,
    threat_indicators JSONB,
    metadata JSONB
);
```

### Network Analytics
```sql
CREATE TABLE network_analytics (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(15, 2) NOT NULL,
    metric_unit VARCHAR(20),
    source VARCHAR(100),
    tags JSONB
);
```

### Threat Intelligence
```sql
CREATE TABLE threat_intelligence (
    id SERIAL PRIMARY KEY,
    indicator_type VARCHAR(50) NOT NULL,
    indicator_value TEXT NOT NULL,
    confidence_level VARCHAR(20) DEFAULT 'medium',
    threat_category VARCHAR(100),
    active BOOLEAN DEFAULT TRUE
);
```

## 🔧 Configuration

### Environment Variables
| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379` |
| `SECRET_KEY` | Flask secret key | `dev-secret-key` |
| `PORT` | Application port | `5000` |

### Redis Cache Keys
- `network:stats:current` - Current network statistics
- `events:realtime` - Real-time security events
- `threats:indicators` - Threat intelligence cache
- `session:{session_id}` - User session data
- `analytics:{metric_name}` - Analytics data cache

## 🧪 Testing

### Run Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app tests/

# Run specific test file
pytest tests/test_app.py
```

### Test Coverage
- **API Endpoints**: All REST endpoints tested
- **Database Operations**: CRUD operations validated
- **Cache Management**: Redis operations tested
- **Integration**: End-to-end workflows tested

## 🚀 Deployment

### Heroku Deployment
```bash
# Create Heroku app
heroku create your-app-name

# Add PostgreSQL
heroku addons:create heroku-postgresql:standard-0

# Add Redis
heroku addons:create heroku-redis:premium-1

# Deploy
git push heroku main
```

### Docker Deployment
```bash
# Build image
docker build -t network-intelligence .

# Run container
docker run -p 5000:5000 \
  -e DATABASE_URL="postgresql://..." \
  -e REDIS_URL="redis://..." \
  network-intelligence
```

## 📊 Monitoring & Logging

### Health Checks
- **Application Health**: `/api/health`
- **Database Status**: Connection monitoring
- **Redis Status**: Cache health monitoring
- **Service Dependencies**: All external services

### Logging
- **Application Logs**: Flask application logging
- **Database Logs**: PostgreSQL query logging
- **Cache Logs**: Redis operation logging
- **Error Tracking**: Comprehensive error handling

## 🔒 Security Considerations

### Data Protection
- **Encryption**: All sensitive data encrypted at rest
- **Access Control**: Role-based access management
- **Audit Logging**: Comprehensive audit trails
- **Input Validation**: Strict input sanitization

### Network Security
- **Rate Limiting**: API rate limiting protection
- **CORS**: Cross-origin resource sharing configuration
- **HTTPS**: Secure communication protocols
- **Firewall Rules**: Network access controls

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:
- 📧 Email: support@networkintelligence.com
- 📖 Documentation: [docs.networkintelligence.com](https://docs.networkintelligence.com)
- 🐛 Issues: [GitHub Issues](https://github.com/your-org/network-intelligence/issues)

## 🔮 Roadmap

### Phase 1: Core Platform ✅
- [x] Basic network monitoring
- [x] Database integration
- [x] Redis caching
- [x] API endpoints
- [x] Dashboard UI

### Phase 2: Advanced Features 🚧
- [ ] Machine learning threat detection
- [ ] Real-time alerting
- [ ] Advanced analytics
- [ ] Integration APIs

### Phase 3: Enterprise Features 📋
- [ ] Multi-tenant support
- [ ] Advanced reporting
- [ ] Compliance frameworks
- [ ] Mobile applications

---

**Built with ❤️ for Network Security Professionals** 