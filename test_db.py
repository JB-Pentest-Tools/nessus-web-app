#!/usr/bin/env python3
"""
Simple test script to verify database initialization
"""

import sqlite3
import os

DATABASE_PATH = 'nessus_analysis.db'

def get_db_connection():
    """Get SQLite database connection"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    """Initialize database with required tables"""
    conn = get_db_connection()
    
    # Scans table - stores upload metadata
    conn.execute('''
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        file_hash TEXT UNIQUE NOT NULL,
        upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        scan_start TEXT,
        scan_end TEXT,
        scanner_name TEXT,
        policy_name TEXT,
        total_hosts INTEGER DEFAULT 0,
        total_issues INTEGER DEFAULT 0
    )
    ''')
    
    # Hosts table - stores host information
    conn.execute('''
    CREATE TABLE IF NOT EXISTS hosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        host_ip TEXT NOT NULL,
        host_fqdn TEXT,
        operating_system TEXT,
        mac_address TEXT,
        host_start TEXT,
        host_end TEXT,
        total_issues INTEGER DEFAULT 0,
        critical_issues INTEGER DEFAULT 0,
        high_issues INTEGER DEFAULT 0,
        medium_issues INTEGER DEFAULT 0,
        low_issues INTEGER DEFAULT 0,
        info_issues INTEGER DEFAULT 0,
        FOREIGN KEY (scan_id) REFERENCES scans (id)
    )
    ''')
    
    # Issues table - stores vulnerability information
    conn.execute('''
    CREATE TABLE IF NOT EXISTS issues (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        plugin_id TEXT NOT NULL,
        plugin_name TEXT NOT NULL,
        severity TEXT NOT NULL,
        risk_factor TEXT,
        cvss_score REAL,
        cvss3_score REAL,
        description TEXT,
        solution TEXT,
        see_also TEXT,
        cve TEXT,
        affected_hosts INTEGER DEFAULT 0,
        FOREIGN KEY (scan_id) REFERENCES scans (id)
    )
    ''')
    
    # Host Issues junction table - many-to-many relationship
    conn.execute('''
    CREATE TABLE IF NOT EXISTS host_issues (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host_id INTEGER NOT NULL,
        issue_id INTEGER NOT NULL,
        port TEXT,
        protocol TEXT,
        service_name TEXT,
        plugin_output TEXT,
        FOREIGN KEY (host_id) REFERENCES hosts (id),
        FOREIGN KEY (issue_id) REFERENCES issues (id)
    )
    ''')
    
    # Create indexes for better performance
    conn.execute('CREATE INDEX IF NOT EXISTS idx_hosts_scan_id ON hosts(scan_id)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_issues_scan_id ON issues(scan_id)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_host_issues_host_id ON host_issues(host_id)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_host_issues_issue_id ON host_issues(issue_id)')
    
    conn.commit()
    conn.close()

def test_database():
    """Test database initialization and basic queries"""
    print("🧪 Testing Nessus Web App Database...")
    
    # Remove existing database if present
    if os.path.exists(DATABASE_PATH):
        os.remove(DATABASE_PATH)
        print("✅ Removed existing database")
    
    # Initialize database
    try:
        init_database()
        print("✅ Database initialization successful")
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        return False
    
    # Test basic queries
    try:
        conn = get_db_connection()
        
        # Test scans table
        result = conn.execute('SELECT COUNT(*) as count FROM scans').fetchone()
        print(f"✅ Scans table query: {result['count']} records")
        
        # Test hosts table
        result = conn.execute('SELECT COUNT(*) as count FROM hosts').fetchone()
        print(f"✅ Hosts table query: {result['count']} records")
        
        # Test issues table
        result = conn.execute('SELECT COUNT(*) as count FROM issues').fetchone()
        print(f"✅ Issues table query: {result['count']} records")
        
        # Test host_issues table
        result = conn.execute('SELECT COUNT(*) as count FROM host_issues').fetchone()
        print(f"✅ Host-Issues table query: {result['count']} records")
        
        # Test dashboard stats query
        result = conn.execute('''
        SELECT 
            COALESCE(SUM(critical_issues), 0) as critical,
            COALESCE(SUM(high_issues), 0) as high,
            COALESCE(SUM(medium_issues), 0) as medium,
            COALESCE(SUM(low_issues), 0) as low,
            COALESCE(SUM(info_issues), 0) as info
        FROM hosts
        ''').fetchone()
        print(f"✅ Dashboard stats query: C:{result['critical']} H:{result['high']} M:{result['medium']} L:{result['low']} I:{result['info']}")
        
        conn.close()
        print("✅ All database queries successful")
        return True
        
    except Exception as e:
        print(f"❌ Database query failed: {e}")
        return False

if __name__ == "__main__":
    success = test_database()
    if success:
        print("\n🎉 Database test PASSED - App should work correctly!")
    else:
        print("\n💥 Database test FAILED - Check errors above")