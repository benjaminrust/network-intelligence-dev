⚠️ **DISCLAIMER**: This project is a proof of concept and not ready for production use. It's provided as a starting point for those looking to build similar integration platforms.

# Network Intelligence - Development

A Flask-based network intelligence and security monitoring application for development environment.

## Features

- Real-time network monitoring and analysis
- Security event detection and alerting
- RESTful API for data ingestion and retrieval
- Web dashboard for visualization
- Redis caching for performance
- PostgreSQL for data persistence

## Quick Start

### Local Development

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set environment variables:
```bash
export FLASK_APP=app.py
export FLASK_ENV=development
export SECRET_KEY=your-secret-key
export DATABASE_URL=your-postgresql-url
export REDIS_URL=your-redis-url
```

3. Run the application:
```bash
flask run
```

### Heroku Deployment

The app is configured for Heroku deployment with:
- `Procfile` for process management
- `runtime.txt` for Python version specification
- `requirements.txt` for dependencies

## API Endpoints

- `GET /` - Dashboard
- `GET /api/health` - Health check
- `GET /api/events` - List security events
- `POST /api/events` - Create new event
- `GET /api/analytics` - Network analytics

## Environment Variables

- `SECRET_KEY` - Flask secret key
- `DATABASE_URL` - PostgreSQL connection string
- `REDIS_URL` - Redis connection string
- `FLASK_ENV` - Environment (development/production)

## Pipeline

This app is part of the network-intelligence pipeline:
- Development: `network-intelligence-dev`
- Staging: `network-intelligence-stage`
- Production: `network-intelligence-prod` 