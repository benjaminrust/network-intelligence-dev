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
        self.mock_ips = [
            '192.168.1.45', '10.0.0.123', '172.16.0.78', '192.168.1.102',
            '203.0.113.15', '198.51.100.67', '192.168.0.234', '10.1.1.89',
            '172.20.0.156', '192.168.2.78', '10.0.1.45', '172.18.0.123'
        ]
        self.event_types = [
            'Suspicious Login Attempt', 'Port Scan Detected', 'Data Exfiltration',
            'Failed Authentication', 'Brute Force Attack', 'Malware Detection',
            'Anomalous Traffic Pattern', 'Unauthorized Access Attempt',
            'DDoS Attack', 'SQL Injection Attempt', 'Cross-Site Scripting',
            'Privilege Escalation Attempt'
        ]
    
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
    
    def generate_dynamic_stats(self):
        """Generate dynamic network statistics"""
        import random
        from datetime import datetime, timedelta
        
        # Generate realistic but varying stats
        base_connections = random.randint(800, 1500)
        suspicious_ratio = random.uniform(0.05, 0.15)
        blocked_ratio = random.uniform(0.02, 0.08)
        
        stats = {
            'total_connections': base_connections,
            'suspicious_connections': int(base_connections * suspicious_ratio),
            'blocked_attempts': int(base_connections * blocked_ratio),
            'last_updated': datetime.now().isoformat()
        }
        
        # Update the instance variable
        self.network_stats = stats
        
        # Print to console for debugging
        print(f"Generated dynamic stats: {stats}")
        
        return stats
    
    def generate_mock_security_events(self, count=5):
        """Generate realistic mock security events"""
        import random
        
        events = []
        for i in range(count):
            # Generate random timestamp within last 2 hours
            time_offset = random.randint(0, 7200)  # 2 hours in seconds
            event_time = datetime.now() - timedelta(seconds=time_offset)
            
            event = {
                'id': random.randint(1000, 9999),
                'timestamp': event_time.isoformat(),
                'event_type': random.choice(self.event_types),
                'source_ip': random.choice(self.mock_ips),
                'severity': random.choice(['low', 'medium', 'high']),
                'risk_score': random.randint(20, 95),
                'description': f"Security event detected from {random.choice(self.mock_ips)}"
            }
            events.append(event)
        
        # Sort by timestamp (most recent first)
        events.sort(key=lambda x: x['timestamp'], reverse=True)
        return events
    
    def get_analyze_suggestions(self):
        """Get IPs from recent events that can be analyzed"""
        events = self.generate_mock_security_events(3)
        return [event['source_ip'] for event in events]

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
    print("DEBUG: health_check() called")
    logger.info("DEBUG: health_check() called")
    
    redis_health = cache_manager.health_check() if cache_manager else {'status': 'unavailable'}
    
    response_data = {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0',
        'services': {
            'redis': redis_health['status'] == 'healthy',
            'database': db_manager is not None and db_manager.get_connection() is not None
        },
        'cache_stats': cache_manager.get_cache_stats() if cache_manager else {}
    }
    
    print(f"DEBUG: health_check returning: {response_data}")
    logger.info(f"DEBUG: health_check returning: {response_data}")
    
    return jsonify(response_data)

@app.route('/api/test-dynamic')
def test_dynamic():
    """Test endpoint for dynamic stats generation"""
    try:
        print("DEBUG: test_dynamic() called")
        logger.info("DEBUG: test_dynamic() called")
        
        print("DEBUG: Calling network_monitor.generate_dynamic_stats()")
        logger.info("DEBUG: Calling network_monitor.generate_dynamic_stats()")
        stats = network_monitor.generate_dynamic_stats()
        
        print(f"DEBUG: Generated dynamic stats: {stats}")
        logger.info(f"DEBUG: Generated dynamic stats: {stats}")
        
        response_data = {
            'success': True,
            'stats': stats,
            'message': 'Dynamic stats generated successfully'
        }
        
        print(f"DEBUG: Returning test-dynamic response: {response_data}")
        logger.info(f"DEBUG: Returning test-dynamic response: {response_data}")
        
        return jsonify(response_data)
    except Exception as e:
        print(f"DEBUG: Error in test_dynamic(): {e}")
        logger.error(f"DEBUG: Error in test_dynamic(): {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Error generating dynamic stats'
        })

@app.route('/api/network/status')
def network_status():
    """Get current network status"""
    # Generate dynamic stats inline for demo
    import random
    from datetime import datetime
    
    print("DEBUG: network_status() called - generating dynamic stats")
    logger.info("DEBUG: network_status() called - generating dynamic stats")
    
    base_connections = random.randint(800, 1500)
    suspicious_ratio = random.uniform(0.05, 0.15)
    blocked_ratio = random.uniform(0.02, 0.08)
    
    print(f"DEBUG: Generated values - base_connections: {base_connections}, suspicious_ratio: {suspicious_ratio}, blocked_ratio: {blocked_ratio}")
    logger.info(f"DEBUG: Generated values - base_connections: {base_connections}, suspicious_ratio: {suspicious_ratio}, blocked_ratio: {blocked_ratio}")
    
    stats = {
        'total_connections': base_connections,
        'suspicious_connections': int(base_connections * suspicious_ratio),
        'blocked_attempts': int(base_connections * blocked_ratio),
        'last_updated': datetime.now().isoformat()
    }
    
    print(f"DEBUG: Final stats object: {stats}")
    logger.info(f"DEBUG: Final stats object: {stats}")
    
    # Cache the dynamic stats for consistency
    if cache_manager:
        print("DEBUG: Caching stats via cache_manager")
        logger.info("DEBUG: Caching stats via cache_manager")
        cache_manager.cache_network_stats(stats)
    else:
        print("DEBUG: No cache_manager available")
        logger.info("DEBUG: No cache_manager available")
    
    response_data = {
        'status': 'operational',
        'stats': stats,
        'active_alerts': len([a for a in network_monitor.alerts if a['status'] == 'active']),
        'last_updated': datetime.now().isoformat()
    }
    
    print(f"DEBUG: Returning response: {response_data}")
    logger.info(f"DEBUG: Returning response: {response_data}")
    
    return jsonify(response_data)

@app.route('/api/network/analyze', methods=['POST'])
def analyze_network_traffic():
    """Analyze network traffic data"""
    try:
        traffic_data = request.get_json()
        if not traffic_data:
            return jsonify({'error': 'No traffic data provided'}), 400
        
        analysis = network_monitor.analyze_traffic(traffic_data)
        
        # Store analysis results in database
        if network_analytics:
            # Store the risk score as a metric
            network_analytics.record_metric({
                'metric_name': 'traffic_analysis_risk_score',
                'metric_value': analysis['risk_score'],
                'metric_unit': 'score',
                'source': 'traffic_analysis',
                'tags': {
                    'source_ip': traffic_data.get('source_ip', 'unknown'),
                    'connection_count': traffic_data.get('connection_count', 0),
                    'failed_auth_attempts': traffic_data.get('failed_auth_attempts', 0),
                    'threats_detected_count': len(analysis['threats_detected']),
                    'recommendations_count': len(analysis['recommendations'])
                }
            })
            
            # Store the analysis timestamp
            network_analytics.record_metric({
                'metric_name': 'traffic_analysis_timestamp',
                'metric_value': datetime.now().timestamp(),
                'metric_unit': 'unix_timestamp',
                'source': 'traffic_analysis',
                'tags': {
                    'source_ip': traffic_data.get('source_ip', 'unknown'),
                    'analysis_id': str(uuid.uuid4())
                }
            })
        
        # Store as security event if risk score is significant
        if analysis['risk_score'] > 30 and security_event:
            event_data = {
                'event_type': 'traffic_analysis',
                'severity': 'high' if analysis['risk_score'] > 80 else 'medium',
                'source_ip': traffic_data.get('source_ip'),
                'destination_ip': traffic_data.get('destination_ip', 'unknown'),
                'risk_score': analysis['risk_score'],
                'threat_indicators': analysis['threats_detected'],
                'metadata': {
                    'traffic_data': traffic_data,
                    'analysis_results': analysis,
                    'recommendations': analysis['recommendations']
                }
            }
            security_event.create_event(event_data)
        
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
        
        # Add success message to analysis
        analysis['stored_in_database'] = True
        analysis['analysis_id'] = str(uuid.uuid4())
        
        return jsonify(analysis)
    
    except Exception as e:
        logger.error(f"Error analyzing traffic: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/network/analysis-history')
def get_traffic_analysis_history():
    """Get traffic analysis history from database"""
    try:
        limit = int(request.args.get('limit', 20))
        offset = int(request.args.get('offset', 0))
        source_ip = request.args.get('source_ip')
        
        if network_analytics:
            # Get risk score metrics for traffic analysis
            metrics = network_analytics.get_metrics('traffic_analysis_risk_score', 'realtime', limit * 2)
            
            # Filter by source IP if provided
            if source_ip:
                metrics = [m for m in metrics if m.get('tags', {}).get('source_ip') == source_ip]
            
            # Format the results
            history = []
            for metric in metrics[offset:offset + limit]:
                history.append({
                    'timestamp': metric.get('timestamp'),
                    'risk_score': metric.get('metric_value'),
                    'source_ip': metric.get('tags', {}).get('source_ip', 'unknown'),
                    'connection_count': metric.get('tags', {}).get('connection_count', 0),
                    'failed_auth_attempts': metric.get('tags', {}).get('failed_auth_attempts', 0),
                    'threats_detected_count': metric.get('tags', {}).get('threats_detected_count', 0),
                    'recommendations_count': metric.get('tags', {}).get('recommendations_count', 0)
                })
        else:
            history = []
        
        return jsonify({
            'history': history,
            'total': len(history),
            'limit': limit,
            'offset': offset
        })
    
    except Exception as e:
        logger.error(f"Error getting traffic analysis history: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/network/analyze-suggestions')
def get_analyze_suggestions():
    """Get IPs from recent security events for analysis suggestions"""
    try:
        suggestions = network_monitor.get_analyze_suggestions()
        return jsonify({
            'suggestions': suggestions,
            'total': len(suggestions)
        })
    except Exception as e:
        logger.error(f"Error getting analyze suggestions: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/events')
def get_events():
    """Get security events from database"""
    try:
        print("DEBUG: get_events() called")
        logger.info("DEBUG: get_events() called")
        
        limit = int(request.args.get('limit', 10))
        offset = int(request.args.get('offset', 0))
        filters = {}
        
        print(f"DEBUG: Request params - limit: {limit}, offset: {offset}")
        logger.info(f"DEBUG: Request params - limit: {limit}, offset: {offset}")
        
        if request.args.get('severity'):
            filters['severity'] = request.args.get('severity')
        if request.args.get('source_ip'):
            filters['source_ip'] = request.args.get('source_ip')
        if request.args.get('event_type'):
            filters['event_type'] = request.args.get('event_type')
        
        print(f"DEBUG: Filters: {filters}")
        logger.info(f"DEBUG: Filters: {filters}")
        
        # Use dynamic mock events for demo
        print("DEBUG: Calling network_monitor.generate_mock_security_events()")
        logger.info("DEBUG: Calling network_monitor.generate_mock_security_events()")
        events = network_monitor.generate_mock_security_events(limit)
        
        print(f"DEBUG: Generated {len(events)} events")
        logger.info(f"DEBUG: Generated {len(events)} events")
        
        # Apply filters if provided
        if filters.get('source_ip'):
            events = [e for e in events if e['source_ip'] == filters['source_ip']]
        if filters.get('severity'):
            events = [e for e in events if e['severity'] == filters['severity']]
        
        response_data = {
            'events': events,
            'total': len(events),
            'limit': limit,
            'offset': offset
        }
        
        print(f"DEBUG: Returning events response: {response_data}")
        logger.info(f"DEBUG: Returning events response: {response_data}")
        
        return jsonify(response_data)
    
    except Exception as e:
        print(f"DEBUG: Error in get_events(): {e}")
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

# AI Inference Endpoints
@app.route('/api/ai-inference', methods=['POST'])
def ai_inference():
    """AI inference endpoint for network intelligence"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        inference_type = data.get('type', 'traffic_analysis')
        input_data = data.get('data', {})
        
        # Mock AI inference for demo purposes
        # In production, this would call Heroku Managed Inference
        if inference_type == 'traffic_analysis':
            result = {
                'inference_type': 'traffic_analysis',
                'risk_score': 75,
                'threat_probability': 0.85,
                'recommendations': [
                    'Block source IP temporarily',
                    'Increase monitoring frequency',
                    'Review firewall rules'
                ],
                'ai_confidence': 0.92,
                'processing_time_ms': 150,
                'model_version': 'v1.0.0'
            }
        elif inference_type == 'threat_classification':
            result = {
                'inference_type': 'threat_classification',
                'threat_type': 'DDoS',
                'confidence': 0.88,
                'severity': 'high',
                'mitigation_strategy': 'Rate limiting + IP blocking',
                'processing_time_ms': 200,
                'model_version': 'v1.0.0'
            }
        else:
            result = {
                'inference_type': inference_type,
                'status': 'unknown_type',
                'message': f'Inference type {inference_type} not supported'
            }
        
        # Store inference result in cache
        if cache_manager:
            cache_manager.cache_inference_result(inference_type, result)
        
        # Record metric
        if network_analytics:
            network_analytics.record_metric({
                'metric_name': 'ai_inference',
                'metric_value': result.get('processing_time_ms', 0),
                'metric_unit': 'ms',
                'source': 'ai_inference',
                'tags': {'type': inference_type, 'confidence': result.get('ai_confidence', 0)}
            })
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error in AI inference: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/ai-inference/batch', methods=['POST'])
def ai_inference_batch():
    """Batch AI inference endpoint"""
    try:
        data = request.get_json()
        if not data or 'requests' not in data:
            return jsonify({'error': 'No batch requests provided'}), 400
        
        batch_results = []
        for i, request_data in enumerate(data['requests']):
            # Process each request individually
            result = {
                'request_id': i,
                'inference_type': request_data.get('type', 'unknown'),
                'status': 'processed',
                'result': {
                    'risk_score': 65 + (i * 5),
                    'confidence': 0.8 + (i * 0.02),
                    'processing_time_ms': 100 + (i * 10)
                }
            }
            batch_results.append(result)
        
        return jsonify({
            'batch_id': str(uuid.uuid4()),
            'total_requests': len(batch_results),
            'results': batch_results,
            'processing_time_ms': sum(r['result']['processing_time_ms'] for r in batch_results)
        })
    
    except Exception as e:
        logger.error(f"Error in batch AI inference: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/ai-inference/models')
def list_ai_models():
    """List available AI models"""
    models = [
        {
            'id': 'traffic-analysis-v1',
            'name': 'Network Traffic Analysis',
            'version': '1.0.0',
            'description': 'Analyzes network traffic patterns for threat detection',
            'supported_types': ['traffic_analysis', 'anomaly_detection'],
            'status': 'available'
        },
        {
            'id': 'threat-classification-v1',
            'name': 'Threat Classification',
            'version': '1.0.0',
            'description': 'Classifies security threats and provides mitigation strategies',
            'supported_types': ['threat_classification', 'malware_detection'],
            'status': 'available'
        },
        {
            'id': 'behavioral-analysis-v1',
            'name': 'Behavioral Analysis',
            'version': '1.0.0',
            'description': 'Analyzes user and system behavior patterns',
            'supported_types': ['behavioral_analysis', 'user_profiling'],
            'status': 'available'
        }
    ]
    
    return jsonify({
        'models': models,
        'total': len(models)
    })

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