import axios from 'axios';

export class AIService {
  private baseUrl: string;

  constructor() {
    this.baseUrl = process.env.NETWORK_INTELLIGENCE_URL || 'https://network-intelligence-dev-0581f075e6f6.herokuapp.com';
  }

  async performInference(appName: string, model: string, inputData: any): Promise<any> {
    try {
      // Call the AI inference endpoint
      const response = await axios.post(`${this.baseUrl}/api/ai-inference`, {
        type: model,
        data: inputData
      });

      const result = response.data;

      return {
        content: [
          {
            type: 'text',
            text: `AI Inference for ${appName} using ${model}:\n\n` +
                  `Inference Type: ${result.inference_type}\n` +
                  `Processing Time: ${result.processing_time_ms}ms\n` +
                  `Model Version: ${result.model_version}\n\n` +
                  `Results:\n` +
                  (result.risk_score ? `- Risk Score: ${result.risk_score}\n` : '') +
                  (result.threat_probability ? `- Threat Probability: ${result.threat_probability}\n` : '') +
                  (result.confidence ? `- Confidence: ${result.confidence}\n` : '') +
                  (result.ai_confidence ? `- AI Confidence: ${result.ai_confidence}\n` : '') +
                  (result.threat_type ? `- Threat Type: ${result.threat_type}\n` : '') +
                  (result.severity ? `- Severity: ${result.severity}\n` : '') +
                  (result.mitigation_strategy ? `- Mitigation: ${result.mitigation_strategy}\n` : '') +
                  `\nRecommendations:\n` +
                  `${result.recommendations?.map((rec: string) => `- ${rec}`).join('\n') || 'None'}`
          }
        ]
      };
    } catch (error) {
      throw new Error(`Failed to perform AI inference for ${appName}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async batchInference(appName: string, requests: any[]): Promise<any> {
    try {
      const response = await axios.post(`${this.baseUrl}/api/ai-inference/batch`, {
        requests: requests
      });

      const result = response.data;

      return {
        content: [
          {
            type: 'text',
            text: `Batch AI Inference for ${appName}:\n\n` +
                  `Batch ID: ${result.batch_id}\n` +
                  `Total Requests: ${result.total_requests}\n` +
                  `Total Processing Time: ${result.processing_time_ms}ms\n\n` +
                  `Results:\n` +
                  `${result.results.map((req: any) => 
                    `Request ${req.request_id}: ${req.inference_type}\n` +
                    `  Risk Score: ${req.result.risk_score}\n` +
                    `  Confidence: ${req.result.confidence}\n` +
                    `  Processing Time: ${req.result.processing_time_ms}ms\n`
                  ).join('\n')}`
          }
        ]
      };
    } catch (error) {
      throw new Error(`Failed to perform batch AI inference for ${appName}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async getModelsResource(): Promise<any> {
    try {
      const response = await axios.get(`${this.baseUrl}/api/ai-inference/models`);
      const models = response.data;

      return {
        contents: [
          {
            uri: 'heroku://ai-models',
            mimeType: 'application/json',
            text: JSON.stringify(models, null, 2)
          }
        ]
      };
    } catch (error) {
      throw new Error(`Failed to get AI models resource: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async listAvailableModels(): Promise<any> {
    try {
      const response = await axios.get(`${this.baseUrl}/api/ai-inference/models`);
      const models = response.data;

      return {
        content: [
          {
            type: 'text',
            text: `Available AI Models:\n\n` +
                  `${models.models.map((model: any) => 
                    `${model.name} (${model.id})\n` +
                    `Version: ${model.version}\n` +
                    `Description: ${model.description}\n` +
                    `Supported Types: ${model.supported_types.join(', ')}\n` +
                    `Status: ${model.status}\n`
                  ).join('\n')}`
          }
        ]
      };
    } catch (error) {
      throw new Error(`Failed to list AI models: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async getInferenceHistory(appName: string, inferenceType: string): Promise<any> {
    try {
      // This would typically call a history endpoint
      // For demo purposes, we'll return a mock response
      const history = [
        {
          timestamp: new Date().toISOString(),
          type: inferenceType,
          risk_score: 75,
          confidence: 0.92,
          processing_time_ms: 150
        },
        {
          timestamp: new Date(Date.now() - 60000).toISOString(),
          type: inferenceType,
          risk_score: 65,
          confidence: 0.88,
          processing_time_ms: 120
        }
      ];

      return {
        content: [
          {
            type: 'text',
            text: `Inference History for ${appName} (${inferenceType}):\n\n` +
                  `${history.map((entry: any) => 
                    `Time: ${entry.timestamp}\n` +
                    `Risk Score: ${entry.risk_score}\n` +
                    `Confidence: ${entry.confidence}\n` +
                    `Processing Time: ${entry.processing_time_ms}ms\n`
                  ).join('\n')}`
          }
        ]
      };
    } catch (error) {
      throw new Error(`Failed to get inference history for ${appName}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
} 