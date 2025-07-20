#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { HerokuService } from './services/heroku.js';
import { NetworkIntelligenceService } from './services/network-intelligence.js';
import { AIService } from './services/ai.js';

class HerokuMCPServer {
  private server: Server;
  private herokuService: HerokuService;
  private networkIntelligenceService: NetworkIntelligenceService;
  private aiService: AIService;

  constructor() {
    this.server = new Server(
      {
        name: 'heroku-mcp-server',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
          resources: {},
        },
      }
    );

    this.herokuService = new HerokuService();
    this.networkIntelligenceService = new NetworkIntelligenceService();
    this.aiService = new AIService();

    this.setupToolHandlers();
    this.setupResourceHandlers();
  }

  private setupToolHandlers() {
    // Heroku App Management
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          // App Management
          {
            name: 'list_heroku_apps',
            description: 'List all Heroku apps with their status and configuration',
            inputSchema: {
              type: 'object',
              properties: {
                all: {
                  type: 'boolean',
                  description: 'Show owned apps and collaborator access',
                  default: false
                }
              }
            }
          },
          {
            name: 'get_heroku_app_info',
            description: 'Get detailed information about a specific Heroku app',
            inputSchema: {
              type: 'object',
              properties: {
                app: {
                  type: 'string',
                  description: 'Target app name'
                }
              },
              required: ['app']
            }
          },
          {
            name: 'deploy_to_heroku',
            description: 'Deploy application to Heroku with environment configuration',
            inputSchema: {
              type: 'object',
              properties: {
                app: {
                  type: 'string',
                  description: 'Target app name'
                },
                environment: {
                  type: 'string',
                  enum: ['development', 'staging', 'production'],
                  description: 'Target environment'
                }
              },
              required: ['app', 'environment']
            }
          },
          {
            name: 'scale_heroku_app',
            description: 'Scale Heroku app dynos',
            inputSchema: {
              type: 'object',
              properties: {
                app: {
                  type: 'string',
                  description: 'Target app name'
                },
                dyno_type: {
                  type: 'string',
                  description: 'Dyno type (web, worker, etc.)'
                },
                quantity: {
                  type: 'number',
                  description: 'Number of dynos'
                },
                size: {
                  type: 'string',
                  description: 'Dyno size (Standard-1X, Standard-2X, etc.)'
                }
              },
              required: ['app', 'dyno_type', 'quantity']
            }
          },
          // Database Management
          {
            name: 'query_heroku_database',
            description: 'Execute SQL query on Heroku PostgreSQL database',
            inputSchema: {
              type: 'object',
              properties: {
                app: {
                  type: 'string',
                  description: 'Target app name'
                },
                query: {
                  type: 'string',
                  description: 'SQL query to execute'
                }
              },
              required: ['app', 'query']
            }
          },
          // AI Inference
          {
            name: 'ai_inference',
            description: 'Perform AI inference using Heroku Managed Inference',
            inputSchema: {
              type: 'object',
              properties: {
                app: {
                  type: 'string',
                  description: 'Target app name'
                },
                model: {
                  type: 'string',
                  description: 'AI model to use'
                },
                input_data: {
                  type: 'object',
                  description: 'Input data for inference'
                }
              },
              required: ['app', 'model', 'input_data']
            }
          },
          // Network Intelligence
          {
            name: 'analyze_network_traffic',
            description: 'Analyze network traffic for security threats',
            inputSchema: {
              type: 'object',
              properties: {
                app: {
                  type: 'string',
                  description: 'Target app name'
                },
                traffic_data: {
                  type: 'object',
                  description: 'Network traffic data to analyze'
                }
              },
              required: ['app', 'traffic_data']
            }
          }
        ]
      };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'list_heroku_apps':
            return await this.herokuService.listApps(args.all || false);

          case 'get_heroku_app_info':
            return await this.herokuService.getAppInfo(args.app);

          case 'deploy_to_heroku':
            return await this.herokuService.deployApp(args.app, args.environment);

          case 'scale_heroku_app':
            return await this.herokuService.scaleApp(args.app, args.dyno_type, args.quantity, args.size);

          case 'query_heroku_database':
            return await this.herokuService.queryDatabase(args.app, args.query);

          case 'ai_inference':
            return await this.aiService.performInference(args.app, args.model, args.input_data);

          case 'analyze_network_traffic':
            return await this.networkIntelligenceService.analyzeTraffic(args.app, args.traffic_data);

          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        return {
          content: [
            {
              type: 'text',
              text: `Error executing tool ${name}: ${error instanceof Error ? error.message : String(error)}`
            }
          ]
        };
      }
    });
  }

  private setupResourceHandlers() {
    this.server.setRequestHandler(ListResourcesRequestSchema, async () => {
      return {
        resources: [
          {
            uri: 'heroku://apps',
            name: 'Heroku Apps',
            description: 'List of all Heroku applications',
            mimeType: 'application/json'
          },
          {
            uri: 'heroku://pipeline/network-intelligence',
            name: 'Network Intelligence Pipeline',
            description: 'Deployment pipeline for network intelligence app',
            mimeType: 'application/json'
          },
          {
            uri: 'heroku://ai-models',
            name: 'AI Models',
            description: 'Available AI models for inference',
            mimeType: 'application/json'
          }
        ]
      };
    });

    this.server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
      const { uri } = request.params;

      try {
        switch (uri) {
          case 'heroku://apps':
            return await this.herokuService.getAppsResource();

          case 'heroku://pipeline/network-intelligence':
            return await this.herokuService.getPipelineResource();

          case 'heroku://ai-models':
            return await this.aiService.getModelsResource();

          default:
            throw new Error(`Unknown resource: ${uri}`);
        }
      } catch (error) {
        return {
          contents: [
            {
              uri,
              mimeType: 'text/plain',
              text: `Error reading resource ${uri}: ${error instanceof Error ? error.message : String(error)}`
            }
          ]
        };
      }
    });
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Heroku MCP Server started');
  }
}

const server = new HerokuMCPServer();
server.run().catch(console.error); 