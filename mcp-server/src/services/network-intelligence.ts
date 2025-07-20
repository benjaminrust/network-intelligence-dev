import axios from 'axios';

export class NetworkIntelligenceService {
  private baseUrl: string;

  constructor() {
    this.baseUrl = process.env.NETWORK_INTELLIGENCE_URL || 'https://network-intelligence-dev-0581f075e6f6.herokuapp.com';
  }

  async analyzeTraffic(appName: string, trafficData: any): Promise<any> {
    try {
      // Call the network intelligence API
      const response = await axios.post(`${this.baseUrl}/api/network/analyze`, trafficData);
      
      // Also perform AI inference on the traffic data
      const aiResponse = await axios.post(`${this.baseUrl}/api/ai-inference`, {
        type: 'traffic_analysis',
        data: trafficData
      });

      const analysis = response.data;
      const aiResult = aiResponse.data;

      return {
        content: [
          {
            type: 'text',
            text: `Network Traffic Analysis for ${appName}:\n\n` +
                  `Risk Score: ${analysis.risk_score}\n` +
                  `Threats Detected: ${analysis.threats_detected.length}\n` +
                  `AI Confidence: ${aiResult.ai_confidence}\n\n` +
                  `Threats:\n${analysis.threats_detected.map((threat: string) => `- ${threat}`).join('\n')}\n\n` +
                  `Recommendations:\n${analysis.recommendations.map((rec: string) => `- ${rec}`).join('\n')}\n\n` +
                  `AI Recommendations:\n${aiResult.recommendations.map((rec: string) => `- ${rec}`).join('\n')}`
          }
        ]
      };
    } catch (error) {
      throw new Error(`Failed to analyze traffic for ${appName}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async getNetworkStatus(appName: string): Promise<any> {
    try {
      const response = await axios.get(`${this.baseUrl}/api/network/status`);
      const status = response.data;

      return {
        content: [
          {
            type: 'text',
            text: `Network Status for ${appName}:\n\n` +
                  `Status: ${status.status}\n` +
                  `Total Connections: ${status.stats.total_connections}\n` +
                  `Suspicious Connections: ${status.stats.suspicious_connections}\n` +
                  `Blocked Attempts: ${status.stats.blocked_attempts}\n` +
                  `Active Alerts: ${status.active_alerts}\n` +
                  `Last Updated: ${status.last_updated}`
          }
        ]
      };
    } catch (error) {
      throw new Error(`Failed to get network status for ${appName}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async getSecurityAlerts(appName: string): Promise<any> {
    try {
      const response = await axios.get(`${this.baseUrl}/api/alerts`);
      const alerts = response.data;

      return {
        content: [
          {
            type: 'text',
            text: `Security Alerts for ${appName}:\n\n` +
                  `Total Alerts: ${alerts.length}\n\n` +
                  `${alerts.map((alert: any) => 
                    `[${alert.severity.toUpperCase()}] ${alert.type}: ${alert.description}\n` +
                    `Source: ${alert.source_ip} → ${alert.destination_ip}\n` +
                    `Time: ${alert.timestamp}\n`
                  ).join('\n')}`
          }
        ]
      };
    } catch (error) {
      throw new Error(`Failed to get security alerts for ${appName}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async getThreatIntelligence(appName: string): Promise<any> {
    try {
      const response = await axios.get(`${this.baseUrl}/api/threats/indicators`);
      const indicators = response.data;

      return {
        content: [
          {
            type: 'text',
            text: `Threat Intelligence for ${appName}:\n\n` +
                  `Total Indicators: ${indicators.total}\n\n` +
                  `${indicators.indicators.map((indicator: any) => 
                    `[${indicator.confidence.toUpperCase()}] ${indicator.type}: ${indicator.value}\n` +
                    `Description: ${indicator.description}\n` +
                    `Time: ${indicator.timestamp}\n`
                  ).join('\n')}`
          }
        ]
      };
    } catch (error) {
      throw new Error(`Failed to get threat intelligence for ${appName}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async getAnalytics(appName: string, metricName?: string): Promise<any> {
    try {
      const params = metricName ? { metric_name: metricName } : {};
      const response = await axios.get(`${this.baseUrl}/api/analytics/metrics`, { params });
      const analytics = response.data;

      return {
        content: [
          {
            type: 'text',
            text: `Analytics for ${appName}:\n\n` +
                  `Total Metrics: ${analytics.total}\n\n` +
                  `${analytics.metrics.map((metric: any) => 
                    `${metric.metric_name}: ${metric.metric_value} ${metric.metric_unit}\n` +
                    `Source: ${metric.source}\n` +
                    `Time: ${metric.timestamp}\n`
                  ).join('\n')}`
          }
        ]
      };
    } catch (error) {
      throw new Error(`Failed to get analytics for ${appName}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
} 