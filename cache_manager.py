import redis
import json
import logging
from datetime import datetime, timedelta
import threading
import time

logger = logging.getLogger(__name__)

class CacheManager:
    def __init__(self, redis_url):
        self.redis_url = redis_url
        self.redis_client = None
        self.connect()
    
    def connect(self):
        """Connect to Redis"""
        try:
            self.redis_client = redis.from_url(self.redis_url)
            self.redis_client.ping()
            logger.info("Redis connection established")
        except Exception as e:
            logger.error(f"Redis connection failed: {e}")
            self.redis_client = None
    
    def is_connected(self):
        """Check if Redis is connected"""
        if not self.redis_client:
            return False
        try:
            self.redis_client.ping()
            return True
        except:
            return False
    
    # Real-time Network Data
    def cache_network_stats(self, stats_data, ttl=300):
        """Cache network statistics"""
        if not self.is_connected():
            return False
        
        try:
            key = "network:stats:current"
            self.redis_client.setex(key, ttl, json.dumps(stats_data))
            return True
        except Exception as e:
            logger.error(f"Error caching network stats: {e}")
            return False
    
    def get_network_stats(self):
        """Get cached network statistics"""
        if not self.is_connected():
            return None
        
        try:
            key = "network:stats:current"
            data = self.redis_client.get(key)
            return json.loads(data) if data else None
        except Exception as e:
            logger.error(f"Error getting network stats: {e}")
            return None
    
    def cache_realtime_events(self, events_data, ttl=60):
        """Cache real-time security events"""
        if not self.is_connected():
            return False
        
        try:
            key = "events:realtime"
            self.redis_client.setex(key, ttl, json.dumps(events_data))
            return True
        except Exception as e:
            logger.error(f"Error caching real-time events: {e}")
            return False
    
    def get_realtime_events(self):
        """Get cached real-time events"""
        if not self.is_connected():
            return []
        
        try:
            key = "events:realtime"
            data = self.redis_client.get(key)
            return json.loads(data) if data else []
        except Exception as e:
            logger.error(f"Error getting real-time events: {e}")
            return []
    
    # Session Management
    def cache_user_session(self, session_id, session_data, ttl=3600):
        """Cache user session data"""
        if not self.is_connected():
            return False
        
        try:
            key = f"session:{session_id}"
            self.redis_client.setex(key, ttl, json.dumps(session_data))
            return True
        except Exception as e:
            logger.error(f"Error caching user session: {e}")
            return False
    
    def get_user_session(self, session_id):
        """Get cached user session"""
        if not self.is_connected():
            return None
        
        try:
            key = f"session:{session_id}"
            data = self.redis_client.get(key)
            return json.loads(data) if data else None
        except Exception as e:
            logger.error(f"Error getting user session: {e}")
            return None
    
    def delete_user_session(self, session_id):
        """Delete cached user session"""
        if not self.is_connected():
            return False
        
        try:
            key = f"session:{session_id}"
            self.redis_client.delete(key)
            return True
        except Exception as e:
            logger.error(f"Error deleting user session: {e}")
            return False
    
    # Threat Intelligence Cache
    def cache_threat_indicators(self, indicators, ttl=1800):
        """Cache threat intelligence indicators"""
        if not self.is_connected():
            return False
        
        try:
            key = "threats:indicators"
            self.redis_client.setex(key, ttl, json.dumps(indicators))
            return True
        except Exception as e:
            logger.error(f"Error caching threat indicators: {e}")
            return False
    
    def get_threat_indicators(self):
        """Get cached threat indicators"""
        if not self.is_connected():
            return []
        
        try:
            key = "threats:indicators"
            data = self.redis_client.get(key)
            return json.loads(data) if data else []
        except Exception as e:
            logger.error(f"Error getting threat indicators: {e}")
            return []
    
    def check_threat_indicator(self, indicator_value):
        """Quick check for threat indicator in cache"""
        if not self.is_connected():
            return None
        
        try:
            key = f"threat:check:{indicator_value}"
            result = self.redis_client.get(key)
            if result:
                return json.loads(result)
            return None
        except Exception as e:
            logger.error(f"Error checking threat indicator: {e}")
            return None
    
    def cache_threat_check(self, indicator_value, result, ttl=3600):
        """Cache threat check result"""
        if not self.is_connected():
            return False
        
        try:
            key = f"threat:check:{indicator_value}"
            self.redis_client.setex(key, ttl, json.dumps(result))
            return True
        except Exception as e:
            logger.error(f"Error caching threat check: {e}")
            return False
    
    # Analytics Cache
    def cache_analytics(self, metric_name, data, ttl=300):
        """Cache analytics data"""
        if not self.is_connected():
            return False
        
        try:
            key = f"analytics:{metric_name}"
            self.redis_client.setex(key, ttl, json.dumps(data))
            return True
        except Exception as e:
            logger.error(f"Error caching analytics: {e}")
            return False
    
    def get_analytics(self, metric_name):
        """Get cached analytics data"""
        if not self.is_connected():
            return None
        
        try:
            key = f"analytics:{metric_name}"
            data = self.redis_client.get(key)
            return json.loads(data) if data else None
        except Exception as e:
            logger.error(f"Error getting analytics: {e}")
            return None
    
    # AI Inference Cache
    def cache_inference_result(self, inference_type, result, ttl=1800):
        """Cache AI inference result"""
        if not self.is_connected():
            return False
        
        try:
            key = f"inference:{inference_type}:{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.redis_client.setex(key, ttl, json.dumps(result))
            
            # Also cache latest result for quick access
            latest_key = f"inference:latest:{inference_type}"
            self.redis_client.setex(latest_key, ttl, json.dumps(result))
            return True
        except Exception as e:
            logger.error(f"Error caching inference result: {e}")
            return False
    
    def get_latest_inference_result(self, inference_type):
        """Get latest inference result for a type"""
        if not self.is_connected():
            return None
        
        try:
            key = f"inference:latest:{inference_type}"
            data = self.redis_client.get(key)
            return json.loads(data) if data else None
        except Exception as e:
            logger.error(f"Error getting latest inference result: {e}")
            return None
    
    def get_inference_history(self, inference_type, limit=10):
        """Get inference history for a type"""
        if not self.is_connected():
            return []
        
        try:
            pattern = f"inference:{inference_type}:*"
            keys = self.redis_client.keys(pattern)
            keys.sort(reverse=True)  # Most recent first
            
            results = []
            for key in keys[:limit]:
                data = self.redis_client.get(key)
                if data:
                    results.append(json.loads(data))
            
            return results
        except Exception as e:
            logger.error(f"Error getting inference history: {e}")
            return []
    
    # Rate Limiting
    def check_rate_limit(self, key, limit, window):
        """Check rate limit for a key"""
        if not self.is_connected():
            return True  # Allow if Redis is down
        
        try:
            current = self.redis_client.get(key)
            if current is None:
                self.redis_client.setex(key, window, 1)
                return True
            elif int(current) < limit:
                self.redis_client.incr(key)
                return True
            else:
                return False
        except Exception as e:
            logger.error(f"Error checking rate limit: {e}")
            return True  # Allow if error
    
    # Pub/Sub for Real-time Updates
    def publish_event(self, channel, event_data):
        """Publish event to Redis channel"""
        if not self.is_connected():
            return False
        
        try:
            self.redis_client.publish(channel, json.dumps(event_data))
            return True
        except Exception as e:
            logger.error(f"Error publishing event: {e}")
            return False
    
    def subscribe_to_events(self, channel, callback):
        """Subscribe to Redis channel for events"""
        if not self.is_connected():
            return False
        
        try:
            pubsub = self.redis_client.pubsub()
            pubsub.subscribe(channel)
            
            def listener():
                for message in pubsub.listen():
                    if message['type'] == 'message':
                        try:
                            data = json.loads(message['data'])
                            callback(data)
                        except Exception as e:
                            logger.error(f"Error processing message: {e}")
            
            thread = threading.Thread(target=listener, daemon=True)
            thread.start()
            return True
        except Exception as e:
            logger.error(f"Error subscribing to events: {e}")
            return False
    
    # Cache Management
    def clear_cache(self, pattern="*"):
        """Clear cache by pattern"""
        if not self.is_connected():
            return False
        
        try:
            keys = self.redis_client.keys(pattern)
            if keys:
                self.redis_client.delete(*keys)
            return True
        except Exception as e:
            logger.error(f"Error clearing cache: {e}")
            return False
    
    def get_cache_stats(self):
        """Get cache statistics"""
        if not self.is_connected():
            return {}
        
        try:
            info = self.redis_client.info()
            return {
                'connected_clients': info.get('connected_clients', 0),
                'used_memory_human': info.get('used_memory_human', '0B'),
                'total_commands_processed': info.get('total_commands_processed', 0),
                'keyspace_hits': info.get('keyspace_hits', 0),
                'keyspace_misses': info.get('keyspace_misses', 0)
            }
        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
            return {}
    
    # Health Check
    def health_check(self):
        """Check Redis health"""
        if not self.is_connected():
            return {
                'status': 'unhealthy',
                'error': 'Redis not connected'
            }
        
        try:
            self.redis_client.ping()
            return {
                'status': 'healthy',
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e)
            } 