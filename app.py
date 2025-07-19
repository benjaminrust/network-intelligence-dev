from flask import Flask, request, jsonify, render_template, session
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
import uuid
import requests
from models import DatabaseManager, SecurityEvent, NetworkAnalytics, ThreatIntelligence, UserSession
from cache_manager import CacheManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['REDIS_URL'] = os.environ.get('REDIS_URL', 'redis://localhost:6379')
app.config['DATABASE_URL'] = os.environ.get('DATABASE_URL')

# Initialize database manager
db_manager = DatabaseManager(app.config['DATABASE_URL']) if app.config['DATABASE_URL'] else None

# Initialize cache manager
cache_manager = CacheManager(app.config['REDIS_URL'])

# Initialize model classes
security_event = SecurityEvent(db_manager) if db_manager else None
network_analytics = NetworkAnalytics(db_manager) if db_manager else None
threat_intelligence = ThreatIntelligence(db_manager) if db_manager else None
user_session = UserSession(db_manager) if db_manager else None

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
        
        # Check threat intelligence cache first
        if cache_manager and traffic_data.get('source_ip'):
            threat_check = cache_manager.check_threat_indicator(traffic_data['source_ip'])
            if threat_check:
                analysis['risk_score'] += 80
                analysis['threats_detected'].append(f"Known threat IP: {traffic_data['source_ip']}")
                analysis['recommendations'].append('Block IP immediately')
        
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
        
        # Store analysis in database
        if network_analytics:
            network_analytics.record_metric({
                'metric_name': 'traffic_analysis_risk_score',
                'metric_value': analysis['risk_score'],
                'metric_unit': 'score',
                'source': 'network_monitor',
                'tags': {'source_ip': traffic_data.get('source_ip', 'unknown')}
            })
        
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
        
        # Store in database
        if security_event:
            security_event.create_event({
                'event_type': alert_data.get('type', 'unknown'),
                'severity': alert_data.get('severity', 'medium'),
                'source_ip': alert_data.get('source_ip'),
                'destination_ip': alert_data.get('destination_ip'),
                'risk_score': 80 if alert_data.get('severity') == 'high' else 50,
                'metadata': alert_data
            })
        
        # Store in Redis for real-time access
        if cache_manager:
            cache_manager.publish_event('security_alerts', alert)
        
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
    redis_health = cache_manager.health_check() if cache_manager else {'status': 'unavailable'}
    
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'services': {
            'redis': redis_health['status'] == 'healthy',
            'database': db_manager is not None and db_manager.get_connection() is not None
        },
        'cache_stats': cache_manager.get_cache_stats() if cache_manager else {}
    })

@app.route('/api/network/status')
def network_status():
    """Get current network status"""
    # Try to get cached stats first
    cached_stats = cache_manager.get_network_stats() if cache_manager else None
    if cached_stats:
        stats = cached_stats
    else:
        stats = network_monitor.network_stats
        if cache_manager:
            cache_manager.cache_network_stats(stats)
    
    return jsonify({
        'status': 'operational',
        'stats': stats,
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

@app.route('/api/events')
def get_events():
    """Get security events from database"""
    try:
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        filters = {}
        
        if request.args.get('severity'):
            filters['severity'] = request.args.get('severity')
        if request.args.get('source_ip'):
            filters['source_ip'] = request.args.get('source_ip')
        if request.args.get('event_type'):
            filters['event_type'] = request.args.get('event_type')
        
        if security_event:
            events = security_event.get_events(limit, offset, filters)
        else:
            events = []
        
        return jsonify({
            'events': events,
            'total': len(events),
            'limit': limit,
            'offset': offset
        })
    
    except Exception as e:
        logger.error(f"Error getting events: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/events', methods=['POST'])
def create_event():
    """Create a new security event"""
    try:
        event_data = request.get_json()
        if not event_data:
            return jsonify({'error': 'No event data provided'}), 400
        
        if security_event:
            event = security_event.create_event(event_data)
            if event:
                return jsonify(event), 201
            else:
                return jsonify({'error': 'Failed to create event'}), 500
        else:
            return jsonify({'error': 'Database not available'}), 503
    
    except Exception as e:
        logger.error(f"Error creating event: {e}")
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
    # Try cache first
    cached_indicators = cache_manager.get_threat_indicators() if cache_manager else []
    if cached_indicators:
        indicators = cached_indicators
    else:
        indicators = network_monitor.threat_indicators
        if cache_manager:
            cache_manager.cache_threat_indicators(indicators)
    
    return jsonify({
        'indicators': indicators,
        'total': len(indicators)
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
        
        # Store in database
        if threat_intelligence:
            threat_intelligence.add_indicator(indicator_data)
        
        # Update cache
        if cache_manager:
            cache_manager.cache_threat_indicators(network_monitor.threat_indicators)
        
        return jsonify(indicator), 201
    
    except Exception as e:
        logger.error(f"Error adding threat indicator: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/analytics/metrics')
def get_analytics():
    """Get network analytics"""
    try:
        metric_name = request.args.get('metric_name')
        period = request.args.get('period', 'realtime')
        limit = int(request.args.get('limit', 100))
        
        if network_analytics:
            metrics = network_analytics.get_metrics(metric_name, period, limit)
        else:
            metrics = []
        
        return jsonify({
            'metrics': metrics,
            'total': len(metrics)
        })
    
    except Exception as e:
        logger.error(f"Error getting analytics: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/analytics/metrics', methods=['POST'])
def record_metric():
    """Record a new metric"""
    try:
        metric_data = request.get_json()
        if not metric_data:
            return jsonify({'error': 'No metric data provided'}), 400
        
        if network_analytics:
            metric = network_analytics.record_metric(metric_data)
            if metric:
                return jsonify(metric), 201
            else:
                return jsonify({'error': 'Failed to record metric'}), 500
        else:
            return jsonify({'error': 'Database not available'}), 503
    
    except Exception as e:
        logger.error(f"Error recording metric: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/sessions', methods=['POST'])
def create_session():
    """Create a new user session"""
    try:
        session_data = request.get_json()
        if not session_data:
            return jsonify({'error': 'No session data provided'}), 400
        
        session_id = str(uuid.uuid4())
        session_data['session_id'] = session_id
        
        if user_session:
            session_record = user_session.create_session(session_data)
            if session_record:
                # Cache session
                if cache_manager:
                    cache_manager.cache_user_session(session_id, session_record)
                return jsonify(session_record), 201
            else:
                return jsonify({'error': 'Failed to create session'}), 500
        else:
            return jsonify({'error': 'Database not available'}), 503
    
    except Exception as e:
        logger.error(f"Error creating session: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/sessions/<session_id>')
def get_session(session_id):
    """Get user session"""
    try:
        # Try cache first
        if cache_manager:
            session_data = cache_manager.get_user_session(session_id)
            if session_data:
                return jsonify(session_data)
        
        return jsonify({'error': 'Session not found'}), 404
    
    except Exception as e:
        logger.error(f"Error getting session: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/cache/stats')
def get_cache_stats():
    """Get cache statistics"""
    try:
        stats = cache_manager.get_cache_stats() if cache_manager else {}
        return jsonify(stats)
    
    except Exception as e:
        logger.error(f"Error getting cache stats: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/cache/clear', methods=['POST'])
def clear_cache():
    """Clear cache"""
    try:
        pattern = request.json.get('pattern', '*') if request.json else '*'
        success = cache_manager.clear_cache(pattern) if cache_manager else False
        
        return jsonify({
            'success': success,
            'pattern': pattern
        })
    
    except Exception as e:
        logger.error(f"Error clearing cache: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# Background monitoring task
def background_monitor():
    """Background task for continuous monitoring"""
    while True:
        try:
            # Update network stats
            network_monitor.network_stats['last_updated'] = datetime.now().isoformat()
            
            # Cache updated stats
            if cache_manager:
                cache_manager.cache_network_stats(network_monitor.network_stats)
            
            # Check for stale alerts (older than 24 hours)
            cutoff_time = datetime.now() - timedelta(hours=24)
            for alert in network_monitor.alerts:
                if alert['status'] == 'active':
                    alert_time = datetime.fromisoformat(alert['timestamp'])
                    if alert_time < cutoff_time:
                        alert['status'] = 'stale'
            
            time.sleep(60)  # Check every minute
            
        except Exception as e:
            logger.error(f"Background monitor error: {e}")
            time.sleep(60)

# Start background monitoring
monitor_thread = threading.Thread(target=background_monitor, daemon=True)
monitor_thread.start()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000))) 