from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
import json
import logging
from datetime import datetime, timedelta
import redis
import psycopg2
from psycopg2.extras import RealDictCursor
import threading
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['REDIS_URL'] = os.environ.get('REDIS_URL', 'redis://localhost:6379')
app.config['DATABASE_URL'] = os.environ.get('DATABASE_URL')

# Initialize Redis for caching and real-time data
try:
    redis_client = redis.from_url(app.config['REDIS_URL'])
    redis_client.ping()
    logger.info("Redis connection established")
except Exception as e:
    logger.warning(f"Redis connection failed: {e}")
    redis_client = None

# Database connection
def get_db_connection():
    if app.config['DATABASE_URL']:
        return psycopg2.connect(app.config['DATABASE_URL'])
    return None

# Network Intelligence Core Classes
class NetworkMonitor:
    def __init__(self):
        self.alerts = []
        self.threat_indicators = []
        self.network_stats = {
            'total_connections': 0,
            'suspicious_connections': 0,
            'blocked_attempts': 0,
            'last_updated': datetime.now().isoformat()
        }
    
    def analyze_traffic(self, traffic_data):
        """Analyze network traffic for suspicious patterns"""
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'risk_score': 0,
            'threats_detected': [],
            'recommendations': []
        }
        
        # Basic threat detection logic
        if traffic_data.get('connection_count', 0) > 1000:
            analysis['risk_score'] += 30
            analysis['threats_detected'].append('High connection volume')
            analysis['recommendations'].append('Investigate source IP for DDoS activity')
        
        if traffic_data.get('failed_auth_attempts', 0) > 10:
            analysis['risk_score'] += 50
            analysis['threats_detected'].append('Multiple failed authentication attempts')
            analysis['recommendations'].append('Implement rate limiting and block suspicious IPs')
        
        if traffic_data.get('unusual_ports', []):
            analysis['risk_score'] += 20
            analysis['threats_detected'].append('Unusual port activity detected')
            analysis['recommendations'].append('Review firewall rules and port access')
        
        return analysis
    
    def generate_alert(self, alert_data):
        """Generate security alerts"""
        alert = {
            'id': len(self.alerts) + 1,
            'timestamp': datetime.now().isoformat(),
            'severity': alert_data.get('severity', 'medium'),
            'type': alert_data.get('type', 'unknown'),
            'description': alert_data.get('description', ''),
            'source_ip': alert_data.get('source_ip', ''),
            'destination_ip': alert_data.get('destination_ip', ''),
            'status': 'active'
        }
        
        self.alerts.append(alert)
        
        # Store in Redis for real-time access
        if redis_client:
            redis_client.lpush('network_alerts', json.dumps(alert))
            redis_client.ltrim('network_alerts', 0, 99)  # Keep last 100 alerts
        
        return alert

# Initialize network monitor
network_monitor = NetworkMonitor()

# API Routes
@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'services': {
            'redis': redis_client is not None,
            'database': get_db_connection() is not None
        }
    })

@app.route('/api/network/status')
def network_status():
    """Get current network status"""
    return jsonify({
        'status': 'operational',
        'stats': network_monitor.network_stats,
        'active_alerts': len([a for a in network_monitor.alerts if a['status'] == 'active']),
        'last_updated': datetime.now().isoformat()
    })

@app.route('/api/network/analyze', methods=['POST'])
def analyze_network_traffic():
    """Analyze network traffic data"""
    try:
        traffic_data = request.get_json()
        if not traffic_data:
            return jsonify({'error': 'No traffic data provided'}), 400
        
        analysis = network_monitor.analyze_traffic(traffic_data)
        
        # Generate alert if risk score is high
        if analysis['risk_score'] > 50:
            alert_data = {
                'severity': 'high' if analysis['risk_score'] > 80 else 'medium',
                'type': 'traffic_analysis',
                'description': f"High risk traffic detected (score: {analysis['risk_score']})",
                'source_ip': traffic_data.get('source_ip', 'unknown'),
                'destination_ip': traffic_data.get('destination_ip', 'unknown')
            }
            network_monitor.generate_alert(alert_data)
        
        return jsonify(analysis)
    
    except Exception as e:
        logger.error(f"Error analyzing traffic: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/alerts')
def get_alerts():
    """Get all alerts"""
    status_filter = request.args.get('status', 'all')
    
    if status_filter == 'active':
        alerts = [a for a in network_monitor.alerts if a['status'] == 'active']
    else:
        alerts = network_monitor.alerts
    
    return jsonify({
        'alerts': alerts,
        'total': len(alerts),
        'active': len([a for a in network_monitor.alerts if a['status'] == 'active'])
    })

@app.route('/api/alerts/<int:alert_id>', methods=['PUT'])
def update_alert(alert_id):
    """Update alert status"""
    try:
        data = request.get_json()
        new_status = data.get('status')
        
        if new_status not in ['active', 'resolved', 'investigating']:
            return jsonify({'error': 'Invalid status'}), 400
        
        for alert in network_monitor.alerts:
            if alert['id'] == alert_id:
                alert['status'] = new_status
                return jsonify(alert)
        
        return jsonify({'error': 'Alert not found'}), 404
    
    except Exception as e:
        logger.error(f"Error updating alert: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/threats/indicators')
def get_threat_indicators():
    """Get threat indicators"""
    return jsonify({
        'indicators': network_monitor.threat_indicators,
        'total': len(network_monitor.threat_indicators)
    })

@app.route('/api/threats/indicators', methods=['POST'])
def add_threat_indicator():
    """Add new threat indicator"""
    try:
        indicator_data = request.get_json()
        required_fields = ['type', 'value', 'description']
        
        for field in required_fields:
            if field not in indicator_data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        indicator = {
            'id': len(network_monitor.threat_indicators) + 1,
            'timestamp': datetime.now().isoformat(),
            'type': indicator_data['type'],
            'value': indicator_data['value'],
            'description': indicator_data['description'],
            'confidence': indicator_data.get('confidence', 'medium'),
            'active': True
        }
        
        network_monitor.threat_indicators.append(indicator)
        return jsonify(indicator), 201
    
    except Exception as e:
        logger.error(f"Error adding threat indicator: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# Background monitoring task
def background_monitor():
    """Background task for continuous monitoring"""
    while True:
        try:
            # Update network stats
            network_monitor.network_stats['last_updated'] = datetime.now().isoformat()
            
            # Check for stale alerts (older than 24 hours)
            cutoff_time = datetime.now() - timedelta(hours=24)
            for alert in network_monitor.alerts:
                if alert['status'] == 'active':
                    alert_time = datetime.fromisoformat(alert['timestamp'])
                    if alert_time < cutoff_time:
                        alert['status'] = 'stale'
            
            time.sleep(60)  # Check every minute
            
        except Exception as e:
            logger.error(f"Error in background monitor: {e}")
            time.sleep(60)

# Start background monitoring
monitor_thread = threading.Thread(target=background_monitor, daemon=True)
monitor_thread.start()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False) 