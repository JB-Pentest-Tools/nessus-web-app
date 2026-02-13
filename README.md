# Nessus Web Application

A comprehensive web interface for Nessus XML file analysis and vulnerability management.

## Features

- **📁 File Upload**: Upload Nessus .xml and .nessus files with drag-and-drop support
- **📊 Dashboard**: Interactive dashboard with vulnerability statistics and charts
- **🖥️ Host Analysis**: Detailed host information and vulnerability breakdown
- **⚠️ Issue Management**: Comprehensive vulnerability analysis with CVSS scoring
- **🔧 Admin Panel**: Scan management with single and bulk deletion capabilities
- **💾 SQLite Database**: Fast, local database storage with duplicate detection
- **📱 Responsive Design**: Mobile-friendly interface built with Bootstrap 5

## Screenshots

### Dashboard
View overall vulnerability statistics and recent scan activity.

### Host Analysis
Drill down into individual hosts to see their vulnerability profiles.

### Admin Panel
Manage uploaded scans with powerful deletion and bulk operations.

## Installation

### Prerequisites
- Python 3.8+
- Flask
- SQLite3

### Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/JB-Pentest-Tools/nessus-web-app.git
   cd nessus-web-app
   ```

2. **Create virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Linux/Mac
   # or
   venv\Scripts\activate  # Windows
   ```

3. **Install dependencies**:
   ```bash
   pip install flask
   ```

4. **Run the application**:
   ```bash
   python app.py
   ```

5. **Access the web interface**:
   - Open your browser to `http://localhost:5001`
   - Upload your first Nessus scan to get started

## Usage

### Upload Scans
1. Navigate to the **Upload** tab
2. Select or drag-and-drop your .xml or .nessus files
3. Click **Upload & Process**
4. Files are automatically parsed and stored in the database

### View Results
- **Dashboard**: Get an overview of all vulnerabilities and scan statistics
- **Hosts**: Browse and analyze individual host vulnerabilities
- **Issues**: Review vulnerabilities across all scans with severity filtering

### Manage Scans
- **Admin Panel**: Delete individual scans or perform bulk operations
- **Duplicate Detection**: Automatic prevention of duplicate uploads
- **Data Integrity**: Safe cascade deletion maintains database consistency

## Technical Details

### Database Schema
The application uses SQLite with the following main tables:
- `scans`: Upload metadata and scan information
- `hosts`: Host information and vulnerability counts
- `issues`: Unique vulnerabilities with CVSS data
- `host_issues`: Many-to-many relationship between hosts and issues

### File Processing
- **XML Parsing**: Robust Nessus XML parsing with error handling
- **Deduplication**: File hash-based duplicate detection
- **Data Merging**: Smart merging of overlapping scan data
- **Security**: Safe file handling with extension validation

### API Endpoints
- `GET /api/dashboard-stats`: Dashboard statistics
- `GET /api/admin/scan/<id>/details`: Scan details
- `DELETE /api/admin/scan/<id>`: Delete single scan
- `POST /api/admin/scans/bulk-delete`: Bulk scan deletion

## Security Considerations

- **Input Validation**: All file uploads are validated for type and content
- **SQL Injection Protection**: Uses parameterized queries throughout
- **CSRF Protection**: Built-in Flask CSRF protection
- **File Size Limits**: 100MB maximum file size limit
- **Safe File Handling**: Secure filename processing and temporary file cleanup

## Configuration

### Environment Variables
```bash
# Database path (optional)
DATABASE_PATH=nessus_analysis.db

# Upload directory (optional)
UPLOAD_FOLDER=uploads

# Flask secret key (change in production)
SECRET_KEY=your-secret-key-here
```

### Production Deployment
For production use, consider:
- Using a production WSGI server (e.g., Gunicorn, uWSGI)
- Setting up proper logging
- Implementing authentication/authorization
- Using environment variables for sensitive configuration
- Setting up database backups

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and test thoroughly
4. Commit your changes: `git commit -m 'Add feature'`
5. Push to the branch: `git push origin feature-name`
6. Submit a pull request

## License

This project is part of the JB-Pentest-Tools suite. Please ensure compliance with your organization's security policies when using this tool.

## Changelog

### v1.0.0 (2026-02-13)
- Initial release
- File upload and parsing functionality
- Dashboard with statistics and charts
- Host and vulnerability analysis
- Admin panel with scan management
- Responsive web interface
- SQLite database backend

## Support

For issues, feature requests, or questions:
1. Check existing GitHub issues
2. Create a new issue with detailed information
3. Include error messages, browser info, and steps to reproduce

---

**Built for penetration testers, by penetration testers.**