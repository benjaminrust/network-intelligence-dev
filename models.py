import psycopg2
from psycopg2.extras import RealDictCursor
import json
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self, database_url):
        self.database_url = database_url
        self.init_database()
    
    def get_connection(self):
        """Get database connection"""
        try:
            conn = psycopg2.connect(self.database_url)
            return conn
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            return None
    
    def init_database(self):
        """Initialize database tables"""
        conn = self.get_connection()
        if not conn:
            return
        
        try:
            with conn.cursor() as cur:
                # Security Events Table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS security_events (
                        id SERIAL PRIMARY KEY,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        event_type VARCHAR(100) NOT NULL,
                        severity VARCHAR(20) NOT NULL,
                        source_ip INET,
                        destination_ip INET,
                        source_port INTEGER,
                        destination_port INTEGER,
                        protocol VARCHAR(10),
                        payload_size INTEGER,
                        user_agent TEXT,
                        country_code VARCHAR(3),
                        city VARCHAR(100),
                        latitude DECIMAL(10, 8),
                        longitude DECIMAL(11, 8),
                        risk_score INTEGER DEFAULT 0,
                        threat_indicators JSONB,
                        metadata JSONB,
                        status VARCHAR(20) DEFAULT 'active'
                    )
                """)
                
                # Network Analytics Table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS network_analytics (
                        id SERIAL PRIMARY KEY,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        metric_name VARCHAR(100) NOT NULL,
                        metric_value DECIMAL(15, 2) NOT NULL,
                        metric_unit VARCHAR(20),
                        source VARCHAR(100),
                        tags JSONB,
                        period VARCHAR(20) DEFAULT 'realtime'
                    )
                """)
                
                # Threat Intelligence Table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS threat_intelligence (
                        id SERIAL PRIMARY KEY,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        indicator_type VARCHAR(50) NOT NULL,
                        indicator_value TEXT NOT NULL,
                        confidence_level VARCHAR(20) DEFAULT 'medium',
                        threat_category VARCHAR(100),
                        description TEXT,
                        source VARCHAR(100),
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        active BOOLEAN DEFAULT TRUE,
                        metadata JSONB
                    )
                """)
                
                # User Sessions Table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS user_sessions (
                        id SERIAL PRIMARY KEY,
                        session_id VARCHAR(255) UNIQUE NOT NULL,
                        user_id VARCHAR(100),
                        ip_address INET,
                        user_agent TEXT,
                        login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        logout_time TIMESTAMP,
                        session_duration INTEGER,
                        status VARCHAR(20) DEFAULT 'active',
                        location_data JSONB,
                        risk_factors JSONB
                    )
                """)
                
                # Network Topology Table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS network_topology (
                        id SERIAL PRIMARY KEY,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        node_id VARCHAR(100) NOT NULL,
                        node_type VARCHAR(50) NOT NULL,
                        node_name VARCHAR(255),
                        ip_address INET,
                        mac_address VARCHAR(17),
                        status VARCHAR(20) DEFAULT 'active',
                        connections JSONB,
                        metadata JSONB
                    )
                """)
                
                # Create indexes for better performance
                cur.execute("CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_security_events_source_ip ON security_events(source_ip)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_intelligence_value ON threat_intelligence(indicator_value)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_threat_intelligence_active ON threat_intelligence(active)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_network_analytics_timestamp ON network_analytics(timestamp)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_user_sessions_session_id ON user_sessions(session_id)")
                
            conn.commit()
            logger.info("Database tables initialized successfully")
            
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            conn.rollback()
        finally:
            conn.close()

class SecurityEvent:
    def __init__(self, db_manager):
        self.db_manager = db_manager
    
    def create_event(self, event_data):
        """Create a new security event"""
        conn = self.db_manager.get_connection()
        if not conn:
            return None
        
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    INSERT INTO security_events (
                        event_type, severity, source_ip, destination_ip, 
                        source_port, destination_port, protocol, payload_size,
                        user_agent, country_code, city, latitude, longitude,
                        risk_score, threat_indicators, metadata
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    ) RETURNING *
                """, (
                    event_data.get('event_type'),
                    event_data.get('severity', 'medium'),
                    event_data.get('source_ip'),
                    event_data.get('destination_ip'),
                    event_data.get('source_port'),
                    event_data.get('destination_port'),
                    event_data.get('protocol'),
                    event_data.get('payload_size'),
                    event_data.get('user_agent'),
                    event_data.get('country_code'),
                    event_data.get('city'),
                    event_data.get('latitude'),
                    event_data.get('longitude'),
                    event_data.get('risk_score', 0),
                    json.dumps(event_data.get('threat_indicators', [])),
                    json.dumps(event_data.get('metadata', {}))
                ))
                
                result = cur.fetchone()
                conn.commit()
                return dict(result) if result else None
                
        except Exception as e:
            logger.error(f"Error creating security event: {e}")
            conn.rollback()
            return None
        finally:
            conn.close()
    
    def get_events(self, limit=100, offset=0, filters=None):
        """Get security events with optional filtering"""
        conn = self.db_manager.get_connection()
        if not conn:
            return []
        
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query = "SELECT * FROM security_events WHERE 1=1"
                params = []
                
                if filters:
                    if filters.get('severity'):
                        query += " AND severity = %s"
                        params.append(filters['severity'])
                    
                    if filters.get('source_ip'):
                        query += " AND source_ip = %s"
                        params.append(filters['source_ip'])
                    
                    if filters.get('event_type'):
                        query += " AND event_type = %s"
                        params.append(filters['event_type'])
                    
                    if filters.get('status'):
                        query += " AND status = %s"
                        params.append(filters['status'])
                
                query += " ORDER BY timestamp DESC LIMIT %s OFFSET %s"
                params.extend([limit, offset])
                
                cur.execute(query, params)
                results = cur.fetchall()
                return [dict(row) for row in results]
                
        except Exception as e:
            logger.error(f"Error getting security events: {e}")
            return []
        finally:
            conn.close()

class NetworkAnalytics:
    def __init__(self, db_manager):
        self.db_manager = db_manager
    
    def record_metric(self, metric_data):
        """Record a network metric"""
        conn = self.db_manager.get_connection()
        if not conn:
            return None
        
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    INSERT INTO network_analytics (
                        metric_name, metric_value, metric_unit, source, tags, period
                    ) VALUES (%s, %s, %s, %s, %s, %s) RETURNING *
                """, (
                    metric_data.get('metric_name'),
                    metric_data.get('metric_value'),
                    metric_data.get('metric_unit'),
                    metric_data.get('source'),
                    json.dumps(metric_data.get('tags', {})),
                    metric_data.get('period', 'realtime')
                ))
                
                result = cur.fetchone()
                conn.commit()
                return dict(result) if result else None
                
        except Exception as e:
            logger.error(f"Error recording metric: {e}")
            conn.rollback()
            return None
        finally:
            conn.close()
    
    def get_metrics(self, metric_name=None, period='realtime', limit=100):
        """Get network metrics"""
        conn = self.db_manager.get_connection()
        if not conn:
            return []
        
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query = "SELECT * FROM network_analytics WHERE 1=1"
                params = []
                
                if metric_name:
                    query += " AND metric_name = %s"
                    params.append(metric_name)
                
                if period:
                    query += " AND period = %s"
                    params.append(period)
                
                query += " ORDER BY timestamp DESC LIMIT %s"
                params.append(limit)
                
                cur.execute(query, params)
                results = cur.fetchall()
                return [dict(row) for row in results]
                
        except Exception as e:
            logger.error(f"Error getting metrics: {e}")
            return []
        finally:
            conn.close()

class ThreatIntelligence:
    def __init__(self, db_manager):
        self.db_manager = db_manager
    
    def add_indicator(self, indicator_data):
        """Add a new threat indicator"""
        conn = self.db_manager.get_connection()
        if not conn:
            return None
        
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    INSERT INTO threat_intelligence (
                        indicator_type, indicator_value, confidence_level,
                        threat_category, description, source, metadata
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING *
                """, (
                    indicator_data.get('indicator_type'),
                    indicator_data.get('indicator_value'),
                    indicator_data.get('confidence_level', 'medium'),
                    indicator_data.get('threat_category'),
                    indicator_data.get('description'),
                    indicator_data.get('source'),
                    json.dumps(indicator_data.get('metadata', {}))
                ))
                
                result = cur.fetchone()
                conn.commit()
                return dict(result) if result else None
                
        except Exception as e:
            logger.error(f"Error adding threat indicator: {e}")
            conn.rollback()
            return None
        finally:
            conn.close()
    
    def check_indicator(self, indicator_value, indicator_type=None):
        """Check if an indicator exists in threat intelligence"""
        conn = self.db_manager.get_connection()
        if not conn:
            return None
        
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query = "SELECT * FROM threat_intelligence WHERE indicator_value = %s AND active = TRUE"
                params = [indicator_value]
                
                if indicator_type:
                    query += " AND indicator_type = %s"
                    params.append(indicator_type)
                
                cur.execute(query, params)
                result = cur.fetchone()
                return dict(result) if result else None
                
        except Exception as e:
            logger.error(f"Error checking indicator: {e}")
            return None
        finally:
            conn.close()

class UserSession:
    def __init__(self, db_manager):
        self.db_manager = db_manager
    
    def create_session(self, session_data):
        """Create a new user session"""
        conn = self.db_manager.get_connection()
        if not conn:
            return None
        
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    INSERT INTO user_sessions (
                        session_id, user_id, ip_address, user_agent,
                        location_data, risk_factors
                    ) VALUES (%s, %s, %s, %s, %s, %s) RETURNING *
                """, (
                    session_data.get('session_id'),
                    session_data.get('user_id'),
                    session_data.get('ip_address'),
                    session_data.get('user_agent'),
                    json.dumps(session_data.get('location_data', {})),
                    json.dumps(session_data.get('risk_factors', {}))
                ))
                
                result = cur.fetchone()
                conn.commit()
                return dict(result) if result else None
                
        except Exception as e:
            logger.error(f"Error creating session: {e}")
            conn.rollback()
            return None
        finally:
            conn.close()
    
    def update_session_activity(self, session_id):
        """Update session last activity"""
        conn = self.db_manager.get_connection()
        if not conn:
            return False
        
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE user_sessions 
                    SET last_activity = CURRENT_TIMESTAMP 
                    WHERE session_id = %s
                """, (session_id,))
                
                conn.commit()
                return cur.rowcount > 0
                
        except Exception as e:
            logger.error(f"Error updating session: {e}")
            conn.rollback()
            return False
        finally:
            conn.close() 