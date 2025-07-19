import pytest
import json
from datetime import datetime
from app import app, network_monitor, cache_manager, db_manager

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['DATABASE_URL'] = None  # Disable database for tests
    app.config['REDIS_URL'] = 'redis://localhost:6379'
    
    with app.test_client() as client:
        yield client

class TestHealthCheck:
    def test_health_endpoint(self, client):
        """Test health check endpoint"""
        response = client.get('/api/health')
        data = json.loads(response.data)
        
        assert response.status_code == 200
        assert data['status'] == 'healthy'
        assert 'timestamp' in data
        assert 'version' in data
        assert 'services' in data

class TestNetworkStatus:
    def test_network_status_endpoint(self, client):
        """Test network status endpoint"""
        response = client.get('/api/network/status')
        data = json.loads(response.data)
        
        assert response.status_code == 200
        assert data['status'] == 'operational'
        assert 'stats' in data
        assert 'active_alerts' in data
        assert 'last_updated' in data

class TestTrafficAnalysis:
    def test_analyze_traffic_valid_data(self, client):
        """Test traffic analysis with valid data"""
        traffic_data = {
            'source_ip': '192.168.1.100',
            'connection_count': 500,
            'failed_auth_attempts': 5
        }
        
        response = client.post('/api/network/analyze',
                             data=json.dumps(traffic_data),
                             content_type='application/json')
        data = json.loads(response.data)
        
        assert response.status_code == 200
        assert 'risk_score' in data
        assert 'threats_detected' in data
        assert 'recommendations' in data
        assert isinstance(data['risk_score'], int)
        assert isinstance(data['threats_detected'], list)
        assert isinstance(data['recommendations'], list)

    def test_analyze_traffic_high_risk(self, client):
        """Test traffic analysis with high-risk data"""
        traffic_data = {
            'source_ip': '192.168.1.100',
            'connection_count': 1500,
            'failed_auth_attempts': 15
        }
        
        response = client.post('/api/network/analyze',
                             data=json.dumps(traffic_data),
                             content_type='application/json')
        data = json.loads(response.data)
        
        assert response.status_code == 200
        assert data['risk_score'] > 50  # Should be high risk
        assert len(data['threats_detected']) > 0
        assert len(data['recommendations']) > 0

    def test_analyze_traffic_no_data(self, client):
        """Test traffic analysis with no data"""
        response = client.post('/api/network/analyze',
                             data=json.dumps({}),
                             content_type='application/json')
        data = json.loads(response.data)
        
        assert response.status_code == 200
        assert 'risk_score' in data

    def test_analyze_traffic_invalid_json(self, client):
        """Test traffic analysis with invalid JSON"""
        response = client.post('/api/network/analyze',
                             data='invalid json',
                             content_type='application/json')
        
        assert response.status_code == 400

class TestSecurityEvents:
    def test_get_events_no_database(self, client):
        """Test getting events when database is not available"""
        response = client.get('/api/events')
        data = json.loads(response.data)
        
        assert response.status_code == 200
        assert 'events' in data
        assert 'total' in data
        assert data['events'] == []  # Should be empty without database

    def test_create_event_no_database(self, client):
        """Test creating event when database is not available"""
        event_data = {
            'event_type': 'test_event',
            'severity': 'medium',
            'source_ip': '192.168.1.100'
        }
        
        response = client.post('/api/events',
                             data=json.dumps(event_data),
                             content_type='application/json')
        
        assert response.status_code == 503  # Service unavailable

class TestAlerts:
    def test_get_alerts(self, client):
        """Test getting alerts"""
        response = client.get('/api/alerts')
        data = json.loads(response.data)
        
        assert response.status_code == 200
        assert 'alerts' in data
        assert 'total' in data
        assert 'active' in data
        assert isinstance(data['alerts'], list)

    def test_get_alerts_with_status_filter(self, client):
        """Test getting alerts with status filter"""
        response = client.get('/api/alerts?status=active')
        data = json.loads(response.data)
        
        assert response.status_code == 200
        assert 'alerts' in data

    def test_update_alert(self, client):
        """Test updating alert status"""
        # First create an alert
        alert_data = {
            'severity': 'medium',
            'type': 'test_alert',
            'description': 'Test alert',
            'source_ip': '192.168.1.100'
        }
        
        # Simulate creating an alert
        network_monitor.generate_alert(alert_data)
        
        # Update the alert
        update_data = {'status': 'resolved'}
        response = client.put('/api/alerts/1',
                            data=json.dumps(update_data),
                            content_type='application/json')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'resolved'

    def test_update_alert_invalid_status(self, client):
        """Test updating alert with invalid status"""
        update_data = {'status': 'invalid_status'}
        response = client.put('/api/alerts/1',
                            data=json.dumps(update_data),
                            content_type='application/json')
        
        assert response.status_code == 400

    def test_update_alert_not_found(self, client):
        """Test updating non-existent alert"""
        update_data = {'status': 'resolved'}
        response = client.put('/api/alerts/999',
                            data=json.dumps(update_data),
                            content_type='application/json')
        
        assert response.status_code == 404

class TestThreatIntelligence:
    def test_get_threat_indicators(self, client):
        """Test getting threat indicators"""
        response = client.get('/api/threats/indicators')
        data = json.loads(response.data)
        
        assert response.status_code == 200
        assert 'indicators' in data
        assert 'total' in data
        assert isinstance(data['indicators'], list)

    def test_add_threat_indicator(self, client):
        """Test adding threat indicator"""
        indicator_data = {
            'type': 'ip_address',
            'value': '192.168.1.100',
            'description': 'Test threat indicator',
            'confidence': 'high'
        }
        
        response = client.post('/api/threats/indicators',
                             data=json.dumps(indicator_data),
                             content_type='application/json')
        data = json.loads(response.data)
        
        assert response.status_code == 201
        assert data['type'] == 'ip_address'
        assert data['value'] == '192.168.1.100'
        assert data['confidence'] == 'high'

    def test_add_threat_indicator_missing_fields(self, client):
        """Test adding threat indicator with missing fields"""
        indicator_data = {
            'type': 'ip_address',
            'value': '192.168.1.100'
            # Missing description
        }
        
        response = client.post('/api/threats/indicators',
                             data=json.dumps(indicator_data),
                             content_type='application/json')
        
        assert response.status_code == 400

class TestAnalytics:
    def test_get_analytics_no_database(self, client):
        """Test getting analytics when database is not available"""
        response = client.get('/api/analytics/metrics')
        data = json.loads(response.data)
        
        assert response.status_code == 200
        assert 'metrics' in data
        assert 'total' in data
        assert data['metrics'] == []  # Should be empty without database

    def test_record_metric_no_database(self, client):
        """Test recording metric when database is not available"""
        metric_data = {
            'metric_name': 'test_metric',
            'metric_value': 100,
            'metric_unit': 'count'
        }
        
        response = client.post('/api/analytics/metrics',
                             data=json.dumps(metric_data),
                             content_type='application/json')
        
        assert response.status_code == 503  # Service unavailable

class TestSessions:
    def test_create_session_no_database(self, client):
        """Test creating session when database is not available"""
        session_data = {
            'user_id': 'test_user',
            'ip_address': '192.168.1.100',
            'user_agent': 'Test Browser'
        }
        
        response = client.post('/api/sessions',
                             data=json.dumps(session_data),
                             content_type='application/json')
        
        assert response.status_code == 503  # Service unavailable

    def test_get_session_not_found(self, client):
        """Test getting non-existent session"""
        response = client.get('/api/sessions/nonexistent-session-id')
        
        assert response.status_code == 404

class TestCache:
    def test_get_cache_stats(self, client):
        """Test getting cache statistics"""
        response = client.get('/api/cache/stats')
        data = json.loads(response.data)
        
        assert response.status_code == 200
        # Cache stats should be returned (even if empty)

    def test_clear_cache(self, client):
        """Test clearing cache"""
        response = client.post('/api/cache/clear',
                             data=json.dumps({'pattern': '*'}),
                             content_type='application/json')
        data = json.loads(response.data)
        
        assert response.status_code == 200
        assert 'success' in data
        assert 'pattern' in data

class TestNetworkMonitor:
    def test_network_monitor_initialization(self):
        """Test network monitor initialization"""
        assert network_monitor is not None
        assert hasattr(network_monitor, 'alerts')
        assert hasattr(network_monitor, 'threat_indicators')
        assert hasattr(network_monitor, 'network_stats')

    def test_analyze_traffic_method(self):
        """Test network monitor analyze_traffic method"""
        traffic_data = {
            'source_ip': '192.168.1.100',
            'connection_count': 500,
            'failed_auth_attempts': 5
        }
        
        analysis = network_monitor.analyze_traffic(traffic_data)
        
        assert 'timestamp' in analysis
        assert 'risk_score' in analysis
        assert 'threats_detected' in analysis
        assert 'recommendations' in analysis
        assert isinstance(analysis['risk_score'], int)

    def test_generate_alert_method(self):
        """Test network monitor generate_alert method"""
        alert_data = {
            'severity': 'high',
            'type': 'test_alert',
            'description': 'Test alert description',
            'source_ip': '192.168.1.100'
        }
        
        alert = network_monitor.generate_alert(alert_data)
        
        assert alert['severity'] == 'high'
        assert alert['type'] == 'test_alert'
        assert alert['description'] == 'Test alert description'
        assert alert['source_ip'] == '192.168.1.100'
        assert alert['status'] == 'active'

class TestIntegration:
    def test_full_traffic_analysis_flow(self, client):
        """Test complete traffic analysis flow"""
        # 1. Analyze traffic
        traffic_data = {
            'source_ip': '192.168.1.100',
            'connection_count': 1500,
            'failed_auth_attempts': 20
        }
        
        response = client.post('/api/network/analyze',
                             data=json.dumps(traffic_data),
                             content_type='application/json')
        data = json.loads(response.data)
        
        assert response.status_code == 200
        assert data['risk_score'] > 50  # Should trigger alert
        
        # 2. Check that alerts were generated
        response = client.get('/api/alerts')
        alerts_data = json.loads(response.data)
        
        assert response.status_code == 200
        # Should have at least one alert from the analysis

    def test_health_check_includes_all_services(self, client):
        """Test that health check includes all service statuses"""
        response = client.get('/api/health')
        data = json.loads(response.data)
        
        assert response.status_code == 200
        assert 'services' in data
        assert 'redis' in data['services']
        assert 'database' in data['services']
        assert 'cache_stats' in data

if __name__ == '__main__':
    pytest.main([__file__]) 