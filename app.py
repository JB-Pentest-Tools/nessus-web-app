#!/usr/bin/env python3
"""
Nessus Web Application
A comprehensive web interface for Nessus XML file analysis

Features:
- Upload Nessus XML files
- Dashboard with summary statistics
- Host analysis and drill-down
- Vulnerability analysis and reporting
- SQLite database backend

Author: Dave (OpenClaw)
Created: 2026-02-12
"""

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory
import xml.etree.ElementTree as ET
import sqlite3
import os
import hashlib
from datetime import datetime
from werkzeug.utils import secure_filename
import json

app = Flask(__name__)
app.secret_key = 'nessus-web-app-secret-key-change-in-production'

# Configuration
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'xml', 'nessus'}
DATABASE_PATH = 'nessus_analysis.db'

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.template_filter('datetime_format')
def datetime_format_filter(datetime_str, format_str='%Y-%m-%d %H:%M:%S'):
    """Format datetime string from SQLite"""
    if not datetime_str:
        return 'Unknown'
    
    try:
        # Try to parse SQLite datetime format
        dt = datetime.strptime(datetime_str.split('.')[0], '%Y-%m-%d %H:%M:%S')
        return dt.strftime(format_str)
    except (ValueError, AttributeError):
        # If parsing fails, return the original string
        return str(datetime_str)

def allowed_file(filename):
    """Check if uploaded file has allowed extension"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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

def calculate_file_hash(file_path):
    """Calculate MD5 hash of uploaded file to detect duplicates"""
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def parse_nessus_xml(file_path):
    """Parse Nessus XML file and extract data"""
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        # Extract scan metadata
        policy_name = ""
        scanner_name = ""
        scan_start = ""
        scan_end = ""
        
        # Get policy and preferences
        for policy in root.findall('.//Policy'):
            policy_name = policy.find('policyName')
            if policy_name is not None:
                policy_name = policy_name.text
                break
        
        for preference in root.findall('.//ServerPreferences/preference'):
            name = preference.find('name')
            value = preference.find('value')
            if name is not None and value is not None:
                if name.text == 'scanner_name':
                    scanner_name = value.text
                elif name.text == 'scan_start':
                    scan_start = value.text
                elif name.text == 'scan_end':
                    scan_end = value.text
        
        scan_data = {
            'policy_name': policy_name,
            'scanner_name': scanner_name,
            'scan_start': scan_start,
            'scan_end': scan_end,
            'hosts': [],
            'issues': {}
        }
        
        # Parse hosts and their report items
        for report_host in root.findall('.//ReportHost'):
            host_data = {
                'ip': report_host.get('name', ''),
                'fqdn': '',
                'os': '',
                'mac': '',
                'start': '',
                'end': '',
                'issues': []
            }
            
            # Extract host properties
            for tag in report_host.findall('.//tag'):
                name = tag.get('name', '')
                text = tag.text or ''
                
                if name == 'host-fqdn':
                    host_data['fqdn'] = text
                elif name == 'operating-system':
                    host_data['os'] = text
                elif name == 'mac-address':
                    host_data['mac'] = text
                elif name == 'HOST_START':
                    host_data['start'] = text
                elif name == 'HOST_END':
                    host_data['end'] = text
            
            # Parse vulnerabilities for this host
            for report_item in report_host.findall('.//ReportItem'):
                plugin_id = report_item.get('pluginID', '')
                plugin_name = report_item.get('pluginName', '')
                severity = report_item.get('severity', '0')
                port = report_item.get('port', '')
                protocol = report_item.get('protocol', '')
                service_name = report_item.get('svc_name', '')
                
                # Extract detailed vulnerability information
                description = ""
                solution = ""
                risk_factor = ""
                cvss_score = 0.0
                cvss3_score = 0.0
                see_also = ""
                cve = ""
                plugin_output = ""
                output = ""
                
                for child in report_item:
                    if child.tag == 'description':
                        description = child.text or ""
                    elif child.tag == 'solution':
                        solution = child.text or ""
                    elif child.tag == 'risk_factor':
                        risk_factor = child.text or ""
                    elif child.tag == 'cvss_base_score':
                        try:
                            cvss_score = float(child.text or 0)
                        except ValueError:
                            cvss_score = 0.0
                    elif child.tag == 'cvss3_base_score':
                        try:
                            cvss3_score = float(child.text or 0)
                        except ValueError:
                            cvss3_score = 0.0
                    elif child.tag == 'see_also':
                        see_also = child.text or ""
                    elif child.tag == 'cve':
                        cve = child.text or ""
                    elif child.tag == 'plugin_output':
                        plugin_output = child.text or ""
                    elif child.tag == 'output':
                        output = child.text or ""
                
                # Map severity numbers to text
                severity_map = {'0': 'Info', '1': 'Low', '2': 'Medium', '3': 'High', '4': 'Critical'}
                severity_text = severity_map.get(severity, 'Unknown')
                
                # Combine output and plugin_output for comprehensive information
                combined_output = ""
                if output and plugin_output:
                    if output.strip() != plugin_output.strip():
                        combined_output = f"Output:\n{output}\n\nPlugin Output:\n{plugin_output}"
                    else:
                        combined_output = plugin_output
                elif output:
                    combined_output = output
                elif plugin_output:
                    combined_output = plugin_output
                
                issue_data = {
                    'plugin_id': plugin_id,
                    'plugin_name': plugin_name,
                    'severity': severity_text,
                    'risk_factor': risk_factor,
                    'cvss_score': cvss_score,
                    'cvss3_score': cvss3_score,
                    'description': description,
                    'solution': solution,
                    'see_also': see_also,
                    'cve': cve,
                    'port': port,
                    'protocol': protocol,
                    'service_name': service_name,
                    'plugin_output': combined_output
                }
                
                # Add to host's issues
                host_data['issues'].append(issue_data)
                
                # Track unique issues across all hosts
                if plugin_id not in scan_data['issues']:
                    scan_data['issues'][plugin_id] = {
                        'plugin_id': plugin_id,
                        'plugin_name': plugin_name,
                        'severity': severity_text,
                        'risk_factor': risk_factor,
                        'cvss_score': cvss_score,
                        'cvss3_score': cvss3_score,
                        'description': description,
                        'solution': solution,
                        'see_also': see_also,
                        'cve': cve,
                        'affected_hosts': set()
                    }
                
                scan_data['issues'][plugin_id]['affected_hosts'].add(host_data['ip'])
            
            scan_data['hosts'].append(host_data)
        
        # Convert sets to counts for issues
        for issue in scan_data['issues'].values():
            issue['affected_hosts'] = len(issue['affected_hosts'])
        
        return scan_data
        
    except Exception as e:
        raise Exception(f"Error parsing Nessus XML: {str(e)}")

def save_scan_to_database(scan_data, filename, file_hash):
    """Save parsed scan data to SQLite database with deduplication"""
    conn = get_db_connection()
    
    try:
        # Insert scan metadata
        scan_cursor = conn.execute('''
        INSERT INTO scans (filename, file_hash, scan_start, scan_end, scanner_name, policy_name, total_hosts, total_issues)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            filename,
            file_hash,
            scan_data['scan_start'],
            scan_data['scan_end'],
            scan_data['scanner_name'],
            scan_data['policy_name'],
            len(scan_data['hosts']),
            len(scan_data['issues'])
        ))
        
        scan_id = scan_cursor.lastrowid
        
        # Process issues with deduplication
        issue_id_map = {}
        for issue_data in scan_data['issues'].values():
            # Check if this issue (plugin_id) already exists
            existing_issue = conn.execute('''
            SELECT id, affected_hosts FROM issues WHERE plugin_id = ?
            ''', (issue_data['plugin_id'],)).fetchone()
            
            if existing_issue:
                # Update existing issue with merged data
                new_affected_hosts = max(existing_issue['affected_hosts'], issue_data['affected_hosts'])
                
                conn.execute('''
                UPDATE issues SET 
                    affected_hosts = ?,
                    scan_id = CASE WHEN ? > scan_id THEN ? ELSE scan_id END
                WHERE id = ?
                ''', (
                    new_affected_hosts,
                    scan_id, scan_id,
                    existing_issue['id']
                ))
                issue_id_map[issue_data['plugin_id']] = existing_issue['id']
            else:
                # Insert new issue
                issue_cursor = conn.execute('''
                INSERT INTO issues (scan_id, plugin_id, plugin_name, severity, risk_factor, cvss_score, cvss3_score, 
                                  description, solution, see_also, cve, affected_hosts)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    scan_id,
                    issue_data['plugin_id'],
                    issue_data['plugin_name'],
                    issue_data['severity'],
                    issue_data['risk_factor'],
                    issue_data['cvss_score'],
                    issue_data['cvss3_score'],
                    issue_data['description'],
                    issue_data['solution'],
                    issue_data['see_also'],
                    issue_data['cve'],
                    issue_data['affected_hosts']
                ))
                issue_id_map[issue_data['plugin_id']] = issue_cursor.lastrowid
        
        # Insert/update hosts with deduplication
        for host_data in scan_data['hosts']:
            # Count issues by severity for this host
            critical_count = sum(1 for issue in host_data['issues'] if issue['severity'] == 'Critical')
            high_count = sum(1 for issue in host_data['issues'] if issue['severity'] == 'High')
            medium_count = sum(1 for issue in host_data['issues'] if issue['severity'] == 'Medium')
            low_count = sum(1 for issue in host_data['issues'] if issue['severity'] == 'Low')
            info_count = sum(1 for issue in host_data['issues'] if issue['severity'] == 'Info')
            
            # Check if this host already exists
            existing_host = conn.execute('''
            SELECT id, total_issues, critical_issues, high_issues, medium_issues, low_issues, info_issues 
            FROM hosts WHERE host_ip = ?
            ''', (host_data['ip'],)).fetchone()
            
            if existing_host:
                # Update existing host with merged data (take maximum values)
                new_total = max(existing_host['total_issues'], len(host_data['issues']))
                new_critical = max(existing_host['critical_issues'], critical_count)
                new_high = max(existing_host['high_issues'], high_count)
                new_medium = max(existing_host['medium_issues'], medium_count)
                new_low = max(existing_host['low_issues'], low_count)
                new_info = max(existing_host['info_issues'], info_count)
                
                conn.execute('''
                UPDATE hosts SET 
                    host_fqdn = COALESCE(NULLIF(?, ''), host_fqdn, ?),
                    operating_system = COALESCE(NULLIF(?, ''), operating_system, ?),
                    mac_address = COALESCE(NULLIF(?, ''), mac_address, ?),
                    host_start = COALESCE(NULLIF(?, ''), host_start, ?),
                    host_end = COALESCE(NULLIF(?, ''), host_end, ?),
                    total_issues = ?,
                    critical_issues = ?,
                    high_issues = ?,
                    medium_issues = ?,
                    low_issues = ?,
                    info_issues = ?,
                    scan_id = CASE WHEN ? > scan_id THEN ? ELSE scan_id END
                WHERE id = ?
                ''', (
                    host_data['fqdn'], host_data['fqdn'],
                    host_data['os'], host_data['os'],
                    host_data['mac'], host_data['mac'],
                    host_data['start'], host_data['start'],
                    host_data['end'], host_data['end'],
                    new_total, new_critical, new_high, new_medium, new_low, new_info,
                    scan_id, scan_id,
                    existing_host['id']
                ))
                host_id = existing_host['id']
            else:
                # Insert new host
                host_cursor = conn.execute('''
                INSERT INTO hosts (scan_id, host_ip, host_fqdn, operating_system, mac_address, host_start, host_end,
                                 total_issues, critical_issues, high_issues, medium_issues, low_issues, info_issues)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    scan_id,
                    host_data['ip'],
                    host_data['fqdn'],
                    host_data['os'],
                    host_data['mac'],
                    host_data['start'],
                    host_data['end'],
                    len(host_data['issues']),
                    critical_count,
                    high_count,
                    medium_count,
                    low_count,
                    info_count
                ))
                host_id = host_cursor.lastrowid
            
            # Insert host-issue relationships with deduplication
            for issue in host_data['issues']:
                if issue['plugin_id'] in issue_id_map:
                    # Check if this host-issue relationship already exists
                    existing_relationship = conn.execute('''
                    SELECT id FROM host_issues 
                    WHERE host_id = ? AND issue_id = ? AND port = ? AND protocol = ?
                    ''', (
                        host_id,
                        issue_id_map[issue['plugin_id']],
                        issue['port'],
                        issue['protocol']
                    )).fetchone()
                    
                    if not existing_relationship:
                        # Insert new relationship
                        conn.execute('''
                        INSERT INTO host_issues (host_id, issue_id, port, protocol, service_name, plugin_output)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ''', (
                            host_id,
                            issue_id_map[issue['plugin_id']],
                            issue['port'],
                            issue['protocol'],
                            issue['service_name'],
                            issue['plugin_output']
                        ))
                    else:
                        # Optionally update with more recent plugin output if it's longer/more detailed
                        conn.execute('''
                        UPDATE host_issues SET
                            service_name = COALESCE(NULLIF(?, ''), service_name, ?),
                            plugin_output = CASE 
                                WHEN LENGTH(?) > LENGTH(plugin_output) THEN ? 
                                ELSE plugin_output 
                            END
                        WHERE id = ?
                        ''', (
                            issue['service_name'], issue['service_name'],
                            issue['plugin_output'], issue['plugin_output'],
                            existing_relationship['id']
                        ))
        
        conn.commit()
        return scan_id
        
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

@app.route('/')
def index():
    """Main dashboard page"""
    return redirect(url_for('dashboard'))

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    """Upload tab - file upload functionality"""
    if request.method == 'POST':
        # Check if file was uploaded
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            try:
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
                filename = timestamp + filename
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                
                file.save(file_path)
                
                # Calculate file hash to detect duplicates
                file_hash = calculate_file_hash(file_path)
                
                # Check for duplicates
                conn = get_db_connection()
                existing = conn.execute('SELECT id, filename FROM scans WHERE file_hash = ?', (file_hash,)).fetchone()
                conn.close()
                
                if existing:
                    os.remove(file_path)  # Remove duplicate file
                    flash(f'File already uploaded as: {existing["filename"]}', 'warning')
                    return redirect(url_for('upload'))
                
                # Parse Nessus XML
                flash('Parsing Nessus XML file...', 'info')
                scan_data = parse_nessus_xml(file_path)
                
                # Save to database
                scan_id = save_scan_to_database(scan_data, filename, file_hash)
                
                # Clean up uploaded file (data is now in database)
                os.remove(file_path)
                
                # Check for deduplication by counting actual database records
                conn = get_db_connection()
                total_hosts_in_db = conn.execute('SELECT COUNT(DISTINCT host_ip) FROM hosts').fetchone()[0]
                total_issues_in_db = conn.execute('SELECT COUNT(DISTINCT plugin_id) FROM issues').fetchone()[0]
                conn.close()
                
                # Inform user about processing and potential deduplication
                message = f'Successfully processed {filename}! Found {len(scan_data["hosts"])} hosts and {len(scan_data["issues"])} unique issues.'
                if total_hosts_in_db < sum(1 for _ in scan_data["hosts"]) or total_issues_in_db < len(scan_data["issues"]):
                    message += f' Database now contains {total_hosts_in_db} unique hosts and {total_issues_in_db} unique issues (duplicates merged).'
                
                flash(message, 'success')
                return redirect(url_for('dashboard'))
                
            except Exception as e:
                flash(f'Error processing file: {str(e)}', 'error')
                # Clean up on error
                if 'file_path' in locals() and os.path.exists(file_path):
                    os.remove(file_path)
                return redirect(request.url)
        else:
            flash('Invalid file type. Please upload .xml or .nessus files only.', 'error')
            return redirect(request.url)
    
    # Get recent uploads for display
    # Initialize database to ensure tables exist
    init_database()
    
    conn = get_db_connection()
    
    try:
        recent_scans = conn.execute('''
        SELECT filename, upload_date, total_hosts, total_issues
        FROM scans 
        ORDER BY upload_date DESC 
        LIMIT 10
        ''').fetchall()
    except Exception as e:
        print(f"Database error in upload: {e}")
        recent_scans = []
    finally:
        conn.close()
    
    return render_template('upload.html', recent_scans=recent_scans)

@app.route('/dashboard')
def dashboard():
    """Dashboard tab - summary statistics and charts"""
    # Initialize database to ensure tables exist
    init_database()
    
    conn = get_db_connection()
    
    # Get overall statistics with safe defaults
    stats = {
        'total_scans': 0,
        'total_hosts': 0,
        'total_issues': 0,
        'critical_issues': 0,
        'high_issues': 0,
        'medium_issues': 0,
        'low_issues': 0,
        'info_issues': 0
    }
    
    try:
        # Total scans
        result = conn.execute('SELECT COUNT(*) as count FROM scans').fetchone()
        stats['total_scans'] = result['count'] if result else 0
        
        if stats['total_scans'] > 0:
            # Total unique hosts
            result = conn.execute('SELECT COUNT(DISTINCT host_ip) as count FROM hosts').fetchone()
            stats['total_hosts'] = result['count'] if result else 0
            
            # Issue counts from hosts table
            result = conn.execute('''
            SELECT 
                COALESCE(SUM(critical_issues), 0) as critical,
                COALESCE(SUM(high_issues), 0) as high,
                COALESCE(SUM(medium_issues), 0) as medium,
                COALESCE(SUM(low_issues), 0) as low,
                COALESCE(SUM(info_issues), 0) as info
            FROM hosts
            ''').fetchone()
            
            if result:
                stats['critical_issues'] = result['critical'] or 0
                stats['high_issues'] = result['high'] or 0
                stats['medium_issues'] = result['medium'] or 0
                stats['low_issues'] = result['low'] or 0
                stats['info_issues'] = result['info'] or 0
                stats['total_issues'] = sum([
                    stats['critical_issues'],
                    stats['high_issues'],
                    stats['medium_issues'],
                    stats['low_issues'],
                    stats['info_issues']
                ])
        
        # Get recent scans
        recent_scans = conn.execute('''
        SELECT filename, upload_date, total_hosts, total_issues, scanner_name, policy_name
        FROM scans 
        ORDER BY upload_date DESC 
        LIMIT 5
        ''').fetchall()
        
        # Get top issues by affected hosts
        top_issues = conn.execute('''
        SELECT plugin_name, severity, affected_hosts, cvss3_score
        FROM issues 
        ORDER BY affected_hosts DESC, cvss3_score DESC
        LIMIT 10
        ''').fetchall()
        
    except Exception as e:
        print(f"Database error in dashboard: {e}")
        recent_scans = []
        top_issues = []
    finally:
        conn.close()
    
    return render_template('dashboard.html', stats=stats, recent_scans=recent_scans, top_issues=top_issues)

@app.route('/hosts')
def hosts():
    """Hosts tab - host listing and analysis"""
    # Initialize database to ensure tables exist
    init_database()
    
    conn = get_db_connection()
    
    try:
        # Get all hosts with their scan information
        hosts_data = conn.execute('''
        SELECT h.*, s.filename, s.upload_date, s.scanner_name
        FROM hosts h
        JOIN scans s ON h.scan_id = s.id
        ORDER BY h.critical_issues DESC, h.high_issues DESC, h.total_issues DESC
        ''').fetchall()
    except Exception as e:
        print(f"Database error in hosts: {e}")
        hosts_data = []
    finally:
        conn.close()
    
    return render_template('hosts.html', hosts=hosts_data)

@app.route('/host/<int:host_id>')
def host_detail(host_id):
    """Host detail page with full vulnerability breakdown"""
    # Initialize database to ensure tables exist
    init_database()
    
    conn = get_db_connection()
    
    try:
        # Get host information
        host = conn.execute('''
        SELECT h.*, s.filename, s.upload_date, s.scanner_name, s.policy_name
        FROM hosts h
        JOIN scans s ON h.scan_id = s.id
        WHERE h.id = ?
        ''', (host_id,)).fetchone()
        
        if not host:
            flash('Host not found', 'error')
            return redirect(url_for('hosts'))
        
        # Get all issues for this host
        host_issues = conn.execute('''
        SELECT i.*, hi.port, hi.protocol, hi.service_name, hi.plugin_output
        FROM issues i
        JOIN host_issues hi ON i.id = hi.issue_id
        WHERE hi.host_id = ?
        ORDER BY 
            CASE i.severity 
                WHEN 'Critical' THEN 1
                WHEN 'High' THEN 2
                WHEN 'Medium' THEN 3
                WHEN 'Low' THEN 4
                WHEN 'Info' THEN 5
                ELSE 6
            END,
            i.cvss3_score DESC,
            i.plugin_name
        ''', (host_id,)).fetchall()
        
    except Exception as e:
        print(f"Database error in host_detail: {e}")
        flash('Database error occurred', 'error')
        return redirect(url_for('hosts'))
    finally:
        conn.close()
    
    return render_template('host_detail.html', host=host, issues=host_issues)

@app.route('/issues')
def issues():
    """Issues tab - vulnerability listing and analysis"""
    # Initialize database to ensure tables exist
    init_database()
    
    conn = get_db_connection()
    
    try:
        # Get all unique issues sorted by severity and affected hosts
        issues_data = conn.execute('''
        SELECT i.*, s.filename
        FROM issues i
        JOIN scans s ON i.scan_id = s.id
        ORDER BY 
            CASE i.severity 
                WHEN 'Critical' THEN 1
                WHEN 'High' THEN 2
                WHEN 'Medium' THEN 3
                WHEN 'Low' THEN 4
                WHEN 'Info' THEN 5
                ELSE 6
            END,
            i.affected_hosts DESC,
            i.cvss3_score DESC
        ''').fetchall()
    except Exception as e:
        print(f"Database error in issues: {e}")
        issues_data = []
    finally:
        conn.close()
    
    return render_template('issues.html', issues=issues_data)

@app.route('/issue/<int:issue_id>')
def issue_detail(issue_id):
    """Issue detail page with affected hosts and full information"""
    # Initialize database to ensure tables exist
    init_database()
    
    conn = get_db_connection()
    
    try:
        # Get issue information
        issue = conn.execute('''
        SELECT i.*, s.filename, s.upload_date, s.scanner_name
        FROM issues i
        JOIN scans s ON i.scan_id = s.id
        WHERE i.id = ?
        ''', (issue_id,)).fetchone()
        
        if not issue:
            flash('Issue not found', 'error')
            return redirect(url_for('issues'))
        
        # Get all affected hosts
        affected_hosts = conn.execute('''
        SELECT h.host_ip, h.host_fqdn, h.operating_system, hi.port, hi.protocol, hi.service_name, hi.plugin_output, h.id as host_id
        FROM hosts h
        JOIN host_issues hi ON h.id = hi.host_id
        WHERE hi.issue_id = ?
        ORDER BY h.host_ip
        ''', (issue_id,)).fetchall()
        
    except Exception as e:
        print(f"Database error in issue_detail: {e}")
        flash('Database error occurred', 'error')
        return redirect(url_for('issues'))
    finally:
        conn.close()
    
    return render_template('issue_detail.html', issue=issue, affected_hosts=affected_hosts)

@app.route('/api/dashboard-stats')
def api_dashboard_stats():
    """API endpoint for dashboard statistics (for AJAX updates)"""
    # Initialize database to ensure tables exist
    init_database()
    
    conn = get_db_connection()
    
    try:
        # Severity distribution for charts
        severity_stats = conn.execute('''
        SELECT 
            COALESCE(SUM(critical_issues), 0) as critical,
            COALESCE(SUM(high_issues), 0) as high,
            COALESCE(SUM(medium_issues), 0) as medium,
            COALESCE(SUM(low_issues), 0) as low,
            COALESCE(SUM(info_issues), 0) as info
        FROM hosts
        ''').fetchone()
        
        # Scan timeline data
        scan_timeline = conn.execute('''
        SELECT DATE(upload_date) as date, COUNT(*) as scans
        FROM scans
        GROUP BY DATE(upload_date)
        ORDER BY date DESC
        LIMIT 30
        ''').fetchall()
        
    except Exception as e:
        print(f"Database error in API: {e}")
        severity_stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        scan_timeline = []
    finally:
        conn.close()
    
    return jsonify({
        'severity_distribution': {
            'critical': severity_stats['critical'] if severity_stats else 0,
            'high': severity_stats['high'] if severity_stats else 0,
            'medium': severity_stats['medium'] if severity_stats else 0,
            'low': severity_stats['low'] if severity_stats else 0,
            'info': severity_stats['info'] if severity_stats else 0
        },
        'scan_timeline': [{'date': row['date'], 'scans': row['scans']} for row in scan_timeline] if scan_timeline else []
    })

@app.route('/admin')
def admin():
    """Admin tab - scan management and deletion"""
    # Initialize database to ensure tables exist
    init_database()
    
    conn = get_db_connection()
    
    try:
        # Get all scans with their metadata
        scans = conn.execute('''
        SELECT * FROM scans 
        ORDER BY upload_date DESC
        ''').fetchall()
    except Exception as e:
        print(f"Database error in admin: {e}")
        scans = []
        flash('Database error occurred while loading scans', 'error')
    finally:
        conn.close()
    
    return render_template('admin.html', scans=scans)

@app.route('/api/admin/scan/<int:scan_id>/details')
def api_scan_details(scan_id):
    """API endpoint to get detailed information about a specific scan"""
    # Initialize database to ensure tables exist
    init_database()
    
    conn = get_db_connection()
    
    try:
        # Get scan details
        scan = conn.execute('''
        SELECT * FROM scans WHERE id = ?
        ''', (scan_id,)).fetchone()
        
        if not scan:
            return jsonify({'success': False, 'error': 'Scan not found'}), 404
        
        return jsonify({
            'success': True,
            'scan': {
                'id': scan['id'],
                'filename': scan['filename'],
                'file_hash': scan['file_hash'],
                'upload_date': scan['upload_date'],
                'scan_start': scan['scan_start'],
                'scan_end': scan['scan_end'],
                'scanner_name': scan['scanner_name'],
                'policy_name': scan['policy_name'],
                'total_hosts': scan['total_hosts'],
                'total_issues': scan['total_issues']
            }
        })
    except Exception as e:
        print(f"Database error in scan details API: {e}")
        return jsonify({'success': False, 'error': 'Database error occurred'}), 500
    finally:
        conn.close()

def delete_scan_from_database(scan_id):
    """Delete a scan and all its associated data from the database"""
    conn = get_db_connection()
    
    try:
        # Get scan information before deletion
        scan = conn.execute('SELECT filename FROM scans WHERE id = ?', (scan_id,)).fetchone()
        if not scan:
            raise Exception('Scan not found')
        
        filename = scan['filename']
        
        # Delete in correct order due to foreign key constraints
        
        # 1. Delete host_issues (junction table)
        conn.execute('''
        DELETE FROM host_issues 
        WHERE host_id IN (SELECT id FROM hosts WHERE scan_id = ?)
        ''', (scan_id,))
        
        # 2. Delete hosts
        deleted_hosts = conn.execute('DELETE FROM hosts WHERE scan_id = ?', (scan_id,)).rowcount
        
        # 3. Delete issues (only if they're not referenced by other scans)
        # First, find issues that are only used by this scan
        orphaned_issues = conn.execute('''
        SELECT i.id FROM issues i
        WHERE i.scan_id = ?
        AND NOT EXISTS (
            SELECT 1 FROM host_issues hi
            JOIN hosts h ON hi.host_id = h.id
            WHERE hi.issue_id = i.id AND h.scan_id != ?
        )
        ''', (scan_id, scan_id)).fetchall()
        
        orphaned_issue_count = 0
        for issue in orphaned_issues:
            conn.execute('DELETE FROM issues WHERE id = ?', (issue['id'],))
            orphaned_issue_count += 1
        
        # 4. Delete the scan itself
        conn.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
        
        conn.commit()
        
        return {
            'success': True,
            'filename': filename,
            'deleted_hosts': deleted_hosts,
            'deleted_issues': orphaned_issue_count
        }
        
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

@app.route('/api/admin/scan/<int:scan_id>', methods=['DELETE'])
def api_delete_scan(scan_id):
    """API endpoint to delete a specific scan"""
    try:
        result = delete_scan_from_database(scan_id)
        
        return jsonify({
            'success': True,
            'message': f'Successfully deleted scan "{result["filename"]}" and {result["deleted_hosts"]} associated hosts.'
        })
        
    except Exception as e:
        print(f"Error deleting scan {scan_id}: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/admin/scans/bulk-delete', methods=['POST'])
def api_bulk_delete_scans():
    """API endpoint to delete multiple scans"""
    try:
        data = request.get_json()
        if not data or 'scan_ids' not in data:
            return jsonify({
                'success': False,
                'error': 'No scan IDs provided'
            }), 400
        
        scan_ids = data['scan_ids']
        if not isinstance(scan_ids, list) or not scan_ids:
            return jsonify({
                'success': False,
                'error': 'Invalid scan IDs format'
            }), 400
        
        # Validate scan IDs
        try:
            scan_ids = [int(sid) for sid in scan_ids]
        except ValueError:
            return jsonify({
                'success': False,
                'error': 'Invalid scan ID format'
            }), 400
        
        # Delete each scan
        deleted_scans = []
        total_hosts = 0
        total_issues = 0
        
        for scan_id in scan_ids:
            try:
                result = delete_scan_from_database(scan_id)
                deleted_scans.append(result['filename'])
                total_hosts += result['deleted_hosts']
                total_issues += result['deleted_issues']
            except Exception as e:
                print(f"Error deleting scan {scan_id}: {e}")
                # Continue with other deletions, but log the error
        
        if not deleted_scans:
            return jsonify({
                'success': False,
                'error': 'No scans could be deleted'
            }), 500
        
        return jsonify({
            'success': True,
            'message': f'Successfully deleted {len(deleted_scans)} scan(s) and {total_hosts} associated hosts.',
            'deleted_scans': deleted_scans,
            'deleted_hosts': total_hosts,
            'deleted_issues': total_issues
        })
        
    except Exception as e:
        print(f"Error in bulk delete: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    print("🔧 Initializing Nessus Web Application...")
    
    # Initialize database
    init_database()
    print("✅ Database initialized")
    
    # Create upload directory
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    print("✅ Upload directory ready")
    
    print("🚀 Starting Nessus Web Application")
    print("📊 Access the application at: http://localhost:5001")
    
    app.run(host='0.0.0.0', port=5001, debug=True)