# Heroku MCP Server

A Model Context Protocol (MCP) server for Heroku integration, providing tools and resources for managing Heroku applications, performing AI inference, and analyzing network intelligence data.

## Features

- **Heroku App Management**: List apps, get app info, deploy, and scale dynos
- **Database Operations**: Execute SQL queries on Heroku PostgreSQL databases
- **AI Inference**: Perform AI inference using Heroku Managed Inference
- **Network Intelligence**: Analyze network traffic and security threats
- **Pipeline Management**: Manage Heroku deployment pipelines

## Setup

1. Install dependencies:
```bash
npm install
```

2. Set environment variables:
```bash
export HEROKU_API_TOKEN=your_heroku_token
export NETWORK_INTELLIGENCE_URL=https://your-app.herokuapp.com
```

3. Build the project:
```bash
npm run build
```

4. Start the server:
```bash
npm start
```

## Development

Run in development mode:
```bash
npm run dev
```

## Available Tools

### App Management
- `list_heroku_apps` - List all Heroku apps
- `get_heroku_app_info` - Get detailed app information
- `deploy_to_heroku` - Deploy application to Heroku
- `scale_heroku_app` - Scale app dynos

### Database
- `query_heroku_database` - Execute SQL queries

### AI Inference
- `ai_inference` - Perform AI inference
- `analyze_network_traffic` - Analyze network traffic

## Available Resources

- `heroku://apps` - List of Heroku applications
- `heroku://pipeline/network-intelligence` - Network intelligence pipeline
- `heroku://ai-models` - Available AI models

## Integration with Network Intelligence App

This MCP server integrates with the Network Intelligence FastAPI application to provide:

- Real-time network traffic analysis
- Security threat detection
- AI-powered inference
- Analytics and metrics

## Demo Usage

1. Start the MCP server
2. Connect from VS Code or Cursor
3. Use tools to manage Heroku apps
4. Perform AI inference on network data
5. Monitor security threats and analytics

## Architecture

```
MCP Server
├── HerokuService (App management, deployment)
├── NetworkIntelligenceService (Traffic analysis, security)
└── AIService (Inference, models)
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request 