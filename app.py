# app.py
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
import json
import os
import secrets
import requests

# Import OAuth configuration - prioritize environment variables over config file
# This ensures Railway can override settings
AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN", None)
AUTH0_CLIENT_ID = os.environ.get("AUTH0_CLIENT_ID", None)
AUTH0_CLIENT_SECRET = os.environ.get("AUTH0_CLIENT_SECRET", None)
AUTH0_CALLBACK_URL = os.environ.get("AUTH0_CALLBACK_URL", None)

# If environment variables are not set, try to import from config file
if not all([AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET, AUTH0_CALLBACK_URL]):
    try:
        from oauth_config import AUTH0_DOMAIN as config_domain, AUTH0_CLIENT_ID as config_client_id, \
                                AUTH0_CLIENT_SECRET as config_secret, AUTH0_CALLBACK_URL as config_callback, \
                                DEFAULT_IMAP_SERVERS
        
        # Only use config values if env vars are not set
        AUTH0_DOMAIN = AUTH0_DOMAIN or config_domain
        AUTH0_CLIENT_ID = AUTH0_CLIENT_ID or config_client_id
        AUTH0_CLIENT_SECRET = AUTH0_CLIENT_SECRET or config_secret
        AUTH0_CALLBACK_URL = AUTH0_CALLBACK_URL or config_callback
        
    except ImportError:
        # Fallback defaults if neither env vars nor config file are available
        if not AUTH0_DOMAIN:
            AUTH0_DOMAIN = "your-tenant.auth0.com"
        if not AUTH0_CLIENT_ID:
            AUTH0_CLIENT_ID = "your-client-id"
        if not AUTH0_CLIENT_SECRET:
            AUTH0_CLIENT_SECRET = "your-client-secret"
        if not AUTH0_CALLBACK_URL:
            # Auto-detect callback URL based on HOST header in production
            AUTH0_CALLBACK_URL = "http://localhost:5050/auth/callback"
        
        # Default IMAP servers if not imported
        DEFAULT_IMAP_SERVERS = {
            "gmail.com": "imap.gmail.com",
            "googlemail.com": "imap.gmail.com",
            "outlook.com": "outlook.office365.com",
            "hotmail.com": "outlook.office365.com",
            "live.com": "outlook.office365.com",
            "yahoo.com": "imap.mail.yahoo.com",
            "ymail.com": "imap.mail.yahoo.com",
            "aol.com": "imap.aol.com"
        }
else:
    # If we're using env vars, ensure we have DEFAULT_IMAP_SERVERS
    try:
        from oauth_config import DEFAULT_IMAP_SERVERS
    except ImportError:
        # Default IMAP servers if not imported
        DEFAULT_IMAP_SERVERS = {
            "gmail.com": "imap.gmail.com",
            "googlemail.com": "imap.gmail.com",
            "outlook.com": "outlook.office365.com",
            "hotmail.com": "outlook.office365.com",
            "live.com": "outlook.office365.com",
            "yahoo.com": "imap.mail.yahoo.com",
            "ymail.com": "imap.mail.yahoo.com",
            "aol.com": "imap.aol.com"
        }
import imaplib
import ssl
import base64  # Added for XOAUTH2 authentication
import sys  # Moved to top for logging Python version
from datetime import datetime, timedelta
import email.utils
import logging
import logging.handlers
import time
import socket
import re
import uuid
import threading
import urllib.parse
from collections import defaultdict

app = Flask(__name__)
# Set a secret key for sessions
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(16))

# Set up Auth0 client
oauth = OAuth(app)

# In your auth0 registration (around line 100)
auth0 = oauth.register(
    'auth0',
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=f'https://{AUTH0_DOMAIN}',
    access_token_url=f'https://{AUTH0_DOMAIN}/oauth/token',
    authorize_url=f'https://{AUTH0_DOMAIN}/authorize',
    server_metadata_url=f'https://{AUTH0_DOMAIN}/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid profile email https://mail.google.com/',  # Added Gmail scope
        'token_endpoint_auth_method': 'client_secret_post',
        'response_type': 'code'
    },
    debug=True
)

# Configure logging
log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
numeric_level = getattr(logging, log_level, logging.INFO)

# Set a more aggressive log rotation to prevent logs from growing too large
log_handler = logging.handlers.RotatingFileHandler(
    filename='emailwipe.log',
    maxBytes=1024*1024,  # 1MB file size
    backupCount=3  # Keep 3 backup files
)
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_handler.setFormatter(log_formatter)

# Configure the root logger
logging.basicConfig(level=numeric_level, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[log_handler])
logger = logging.getLogger(__name__)

# Setup circular buffer for error logs 
class CircularLogBuffer(logging.Handler):
    def __init__(self, capacity=100):
        logging.Handler.__init__(self)
        self.capacity = capacity
        self.buffer = []
        self.formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    def emit(self, record):
        # Add new log record to the buffer
        self.buffer.append({
            "timestamp": self.formatter.formatTime(record),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name
        })
        
        # If the buffer is full, remove the oldest record
        if len(self.buffer) > self.capacity:
            self.buffer.pop(0)

# Create and add the buffer handler
log_buffer = CircularLogBuffer(capacity=200)
log_buffer.setLevel(logging.INFO)  # Capture INFO and above to see more details
logging.getLogger().addHandler(log_buffer)

# Log startup information
logger.info(f"Starting EmailWipe, Python version: {sys.version}")
logger.info(f"Using Auth0 domain: {AUTH0_DOMAIN}")
logger.info(f"Using callback URL: {AUTH0_CALLBACK_URL}")

# Add handler for all uncaught exceptions to log them
def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        # Don't log keyboard interrupt
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    
    logger.critical("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))

sys.excepthook = handle_exception

# Default configuration
DEFAULT_CUTOFF_DATE = '01-Jan-2021'
DEFAULT_IMAP_PORT = 993
BATCH_SIZE = 100
CONNECTION_TIMEOUT = 20  # seconds

# Store cleanup progress in memory (will reset on app restart)
# In a production app, consider using Redis or another shared storage
cleanup_progress = {}

# Add a flag to track if process is running to prevent progress from getting stuck
cleanup_running_status = {}

@app.route('/')
def index():
    # Check if demo parameter is provided in URL
    demo_mode = request.args.get('demo', 'false').lower() == 'true'
    return render_template('index.html', demo_mode=demo_mode, debug=app.debug)

@app.route('/demo')
def demo():
    # Redirect to main page with demo parameter
    return redirect('/?demo=true')

@app.route('/health')
def health_check():
    """Simple health check endpoint for monitoring"""
    # Collect system information
    import psutil
    import platform
    
    try:
        process = psutil.Process()
        memory_info = process.memory_info()
        
        return jsonify({
            "status": "ok",
            "version": "1.1",
            "timestamp": datetime.now().isoformat(),
            "auth_configured": bool(AUTH0_DOMAIN and AUTH0_CLIENT_ID and AUTH0_CLIENT_SECRET),
            "uptime_seconds": int(time.time() - process.create_time()),
            "python_version": platform.python_version(),
            "memory_usage_mb": round(memory_info.rss / (1024 * 1024), 2),
            "cpu_percent": process.cpu_percent(interval=0.1),
            "thread_count": len(process.threads())
        })
    except Exception as e:
        logger.error(f"Error in health check: {str(e)}")
        # Simple response if detailed stats fail
        return jsonify({
            "status": "degraded",
            "version": "1.1",
            "timestamp": datetime.now().isoformat(),
            "error": str(e),
            "auth_configured": bool(AUTH0_DOMAIN and AUTH0_CLIENT_ID and AUTH0_CLIENT_SECRET)
        })

@app.route('/debug/logs')
def view_logs():
    """View recent logs for debugging (no authentication for simplicity)"""
    # Get the most recent logs (all logs if format=full is specified)
    show_full = request.args.get('format') == 'full'
    max_logs = len(log_buffer.buffer) if show_full else 75
    logs = log_buffer.buffer[-max_logs:] if log_buffer.buffer else []
    
    # Check if the logs should be returned as JSON or HTML
    if request.args.get('format') == 'json':
        return jsonify(logs)
        
    # Get filter parameter
    level_filter = request.args.get('level', '').upper()
    if level_filter and level_filter in ['INFO', 'WARNING', 'ERROR', 'DEBUG', 'CRITICAL']:
        logs = [log for log in logs if log['level'] == level_filter]
    
    # Generate simple HTML directly without a template
    log_html = '<html><head><title>EmailWipe Debug Logs</title><style>'
    log_html += 'body { font-family: monospace; background: #1a1a2e; color: #e0e0e0; padding: 20px; }'
    log_html += 'h1 { color: #e94560; }'
    log_html += '.log { padding: 8px; margin: 5px 0; border-radius: 4px; }'
    log_html += '.ERROR { background: rgba(255,87,87,0.2); border-left: 4px solid #ff5757; }'
    log_html += '.WARNING { background: rgba(255,177,66,0.2); border-left: 4px solid #ffb142; }'
    log_html += '.INFO { background: rgba(52,152,219,0.1); border-left: 4px solid #3498db; }'
    log_html += '.DEBUG { background: rgba(78, 204, 163,0.1); border-left: 4px solid #4ecca3; }'
    log_html += '.CRITICAL { background: rgba(142, 68, 173,0.2); border-left: 4px solid #8e44ad; }'
    log_html += '.timestamp { color: #a0a0a0; font-size: 0.9em; }'
    log_html += '.message { white-space: pre-wrap; word-break: break-word; }'
    log_html += '.refresh { background: #e94560; color: white; padding: 8px 15px; border: none; border-radius: 4px; cursor: pointer; margin-right: 10px; }'
    log_html += '.filter { background: #16213e; color: white; padding: 8px 15px; border: 1px solid #3498db; border-radius: 4px; cursor: pointer; margin-right: 5px; }'
    log_html += '.filter.active { background: #3498db; }'
    log_html += '.controls { margin: 15px 0; }'
    log_html += '</style></head><body>'
    log_html += '<h1>EmailWipe Debug Logs</h1>'
    
    # Add controls
    log_html += '<div class="controls">'
    log_html += '<button class="refresh" onclick="location.reload()">Refresh Logs</button>'
    
    # Add level filters
    levels = ['INFO', 'WARNING', 'ERROR', 'DEBUG', 'CRITICAL']
    for level in levels:
        active_class = ' active' if level_filter == level else ''
        log_html += f'<a href="?level={level}" class="filter{active_class}">{level}</a>'
    
    # Add all filter to reset
    log_html += '<a href="?" class="filter' + ('' if level_filter else ' active') + '">ALL</a>'
    
    # Add link to full logs
    if not show_full:
        log_html += ' <a href="?format=full" style="margin-left: 15px; color: #4ecca3;">Show All Logs</a>'
    
    log_html += '</div>'
    
    log_html += f'<p>Showing {len(logs)} log entries ({"filtered by " + level_filter if level_filter else "INFO level and above"})</p>'
    
    # Show the logs in reverse chronological order
    for log in reversed(logs):
        log_html += f'<div class="log {log["level"]}">'
        log_html += f'<div class="timestamp">{log["timestamp"]} - {log["level"]} - {log["logger"]}</div>'
        log_html += f'<div class="message">{log["message"]}</div>'
        log_html += '</div>'
    
    log_html += '</body></html>'
    return log_html

# ---- Auth0 OAuth Routes ----

@app.route('/user_info')
def get_user_info():
    """Get user info from session"""
    if 'user_email' in session:
        return jsonify({
            "status": "success",
            "email": session['user_email'],
            "auth_provider": session.get('auth_provider', 'auth0')
        })
    else:
        return jsonify({
            "status": "error",
            "message": "No active user session"
        })

@app.route('/auth/login')
def login():
    """Redirect to Auth0 login page"""
    # Generate a nonce to prevent CSRF attacks
    session['nonce'] = secrets.token_urlsafe(16)
    
    # Get the connection parameter if provided
    connection = request.args.get('connection')
    
    # Log the request for troubleshooting
    logger.info(f"Auth login request with connection: {connection}")
    logger.info(f"Using AUTH0_DOMAIN: {AUTH0_DOMAIN}")
    logger.info(f"Using AUTH0_CLIENT_ID: {AUTH0_CLIENT_ID}")
    logger.info(f"Using AUTH0_CALLBACK_URL: {AUTH0_CALLBACK_URL}")
    
    # Parameters for Auth0
    params = {
        'redirect_uri': AUTH0_CALLBACK_URL,
        'nonce': session['nonce'],
        # Remove audience parameter which can cause issues with social connections
    }
    
    # If a specific connection was requested (like 'google-oauth2')
    if connection:
        params['connection'] = connection
        logger.info(f"Using specific connection: {connection}")
        
        # For Google OAuth specifically
        if connection == 'google-oauth2':
            # Add specific scope for Google
            params['scope'] = 'openid profile email'
            logger.info("Using specific scope for Google OAuth")
    
    # Redirect to Auth0 login page
    try:
        # Log all authorize parameters for debugging
        logger.info(f"Auth0 authorize params: {params}")
        redirect_url = auth0.authorize_redirect(**params)
        logger.info(f"Auth0 redirect successful")
        return redirect_url
    except Exception as e:
        logger.error(f"Auth0 redirect error: {str(e)}", exc_info=True)
        # Provide a user-friendly error
        return render_template('error.html', error="Authentication service temporarily unavailable. Please try again later.")

@app.route('/auth/callback')
def callback():
    """Handle Auth0 callback after login"""
    try:
        # Log all request args for debugging
        logger.info(f"Auth0 callback received with args: {request.args}")
        
        # Check for error in callback
        if 'error' in request.args:
            error = request.args.get('error')
            error_description = request.args.get('error_description', 'Unknown error')
            logger.error(f"Auth0 callback error: {error} - {error_description}")
            return render_template('error.html', error=f"Authentication error: {error_description}")
        
        # Log the callback for debugging
        logger.info(f"Auth0 callback processing, getting token")
        
        try:
            # Get the authorization token with detailed logging
            token = auth0.authorize_access_token()
            logger.info(f"Token received successfully: {token.keys()}")
        except Exception as token_error:
            logger.error(f"Error getting access token: {str(token_error)}", exc_info=True)
            # Check if this is the invalid_client error
            if "invalid_client" in str(token_error).lower():
                return render_template('error.html', error="Authentication configuration error: Client credentials invalid. Please contact support.")
            else:
                return render_template('error.html', error=f"Token error: {str(token_error)}")
        
        # Get the user info from Auth0
        try:
            resp = auth0.get('userinfo')
            userinfo = resp.json()
            logger.info(f"User info received: {userinfo.get('email', 'unknown')}")
        except Exception as userinfo_error:
            logger.error(f"Error getting user info: {str(userinfo_error)}", exc_info=True)
            return render_template('error.html', error="Could not retrieve user information. Please try again.")
        
        # Store user info in session
        session['jwt_token'] = token
        session['user_email'] = userinfo['email']
        
        # Get email domain to determine provider type
        email = userinfo['email']
        domain = email.split('@')[-1].lower()
        logger.info(f"User email domain: {domain}")
        
        # Determine which email provider based on domain
        if domain in ['gmail.com', 'googlemail.com']:
            session['auth_provider'] = 'google'
        elif domain in ['outlook.com', 'hotmail.com', 'live.com']:
            session['auth_provider'] = 'microsoft'
        elif domain in ['yahoo.com', 'ymail.com']:
            session['auth_provider'] = 'yahoo'
        else:
            session['auth_provider'] = 'generic'
        
        # Determine IMAP server based on domain
        for domain_suffix, server in DEFAULT_IMAP_SERVERS.items():
            if domain.endswith(domain_suffix):
                session['imap_server'] = server
                logger.info(f"IMAP server set to {server}")
                break
        else:
            # Default to using a provider-specific server or none if we can't determine
            session['imap_server'] = None
            logger.info("Could not determine IMAP server from domain")
        
        # Redirect to the main page with OAuth success parameter
        return redirect(f'/?oauth=success&provider={session["auth_provider"]}')
    
    except Exception as e:
        logger.error(f"Auth0 callback processing error: {str(e)}", exc_info=True)
        return render_template('error.html', error="Unable to complete authentication. Please check the application settings and try again.")

@app.route('/logout')
def logout():
    """Clear session data and log out from Auth0"""
    # Clear session
    session.clear()
    
    # Determine the root URL from the callback URL
    root_url = AUTH0_CALLBACK_URL.split('/auth/callback')[0] if '/auth/callback' in AUTH0_CALLBACK_URL else 'https://web-production-99c5.up.railway.app/'
    
    # Redirect to Auth0 logout endpoint
    params = {
        'returnTo': root_url,
        'client_id': AUTH0_CLIENT_ID
    }
    logger.info(f"Logout redirecting to: {root_url}")
    return redirect(auth0.api_base_url + '/v2/logout?' + urllib.parse.urlencode(params))

@app.route('/verify', methods=['POST'])
def verify_connection():
    """Verify IMAP server connection and credentials"""
    start_time = time.time()
    
    # Add a safeguard timeout for the entire route
    max_execution_time = 45  # seconds
    
    # Check if Gmail API is available
    use_gmail_api = False
    try:
        # Only import if needed to avoid dependency issues
        import gmail_api_helper
        use_gmail_api = True
        logger.info("Gmail API helper is available")
    except ImportError:
        logger.warning("Gmail API helper is not available. Will use IMAP only.")
        use_gmail_api = False
    
    # Get request data
    try:
        data = request.json
    except Exception as e:
        logger.error(f"Error parsing request JSON: {str(e)}")
        return jsonify({
            "status": "error",
            "message": "Invalid request format. Please ensure you're sending valid JSON."
        })
    
    try:
        # Log full request data for debugging (excluding passwords)
        safe_data = data.copy()
        if 'password' in safe_data:
            safe_data['password'] = '********'
        logger.info(f"Verify connection request: {safe_data}")
        
        # Determine authentication method
        auth_method = data.get('auth_method', 'password')
        
        # Get IMAP server from input
        imap_server = data.get('imap_server')
        if not imap_server:
            return jsonify({"status": "error", "message": "IMAP server is required"})
        
        # Handle OAuth authentication
        if auth_method == 'oauth':
            # Get credentials from session
            if 'jwt_token' in session and 'user_email' in session:
                username = session.get('user_email', '')
                token = session.get('jwt_token', {})
                access_token = token.get('access_token', '')
                
                # Log token presence (not the actual token)
                logger.info(f"OAuth token present: {bool(access_token)}")
                logger.info(f"Session contains: {list(session.keys())}")
                
                # Try to use stored IMAP server if available
                if 'imap_server' in session and not imap_server:
                    imap_server = session['imap_server']
                    
                if not access_token:
                    return jsonify({"status": "error", "message": "No active OAuth session found"})
            else:
                missing_keys = []
                if 'jwt_token' not in session:
                    missing_keys.append('jwt_token')
                if 'user_email' not in session:
                    missing_keys.append('user_email')
                    
                return jsonify({
                    "status": "error", 
                    "message": f"No active OAuth session found. Missing: {', '.join(missing_keys)}"
                })
            
            logger.info(f"Verifying Auth0 OAuth connection for {username} on {imap_server}")
        else:
            # Traditional password authentication
            username = data['username']
            password = data['password']
            logger.info(f"Verifying password connection for {username} on {imap_server}")
        
        # Check if this is Gmail
        is_gmail = 'gmail.com' in imap_server.lower()
        lite_verification = data.get('lite_verification', False)
        
        # For Gmail with OAuth, try to use Gmail API first (most reliable)
        if is_gmail and auth_method == 'oauth':
            if use_gmail_api:
                # Try to use the Gmail API directly
                logger.info("Attempting Gmail API verification")
                try:
                    # Verify the connection with Gmail API
                    connection_success, error_message = gmail_api_helper.verify_gmail_connection(access_token)
                    if connection_success:
                        logger.info("Gmail API connection verified successfully")
                        total_time = time.time() - start_time
                        return jsonify({
                            "status": "success", 
                            "message": "Google authentication verified successfully via Gmail API",
                            "time_taken": f"{total_time:.2f} seconds",
                            "verification_method": "gmail_api",
                            "is_gmail": True
                        })
                    else:
                        # API connection failed, log the reason
                        logger.warning(f"Gmail API verification failed: {error_message}")
                        
                        # Check if this is an authentication error
                        if error_message and any(phrase in error_message.lower() for phrase in ['authentication', 'credentials', 'token', 'permission']):
                            return jsonify({
                                "status": "error",
                                "message": error_message,
                                "time_taken": f"{time.time() - start_time:.2f} seconds",
                                "error_type": "auth_error",
                                "is_gmail": True
                            })
                except Exception as api_error:
                    logger.error(f"Error during Gmail API verification: {str(api_error)}")
            
            # If lite verification is requested or Gmail API failed, try token verification
            if lite_verification or not use_gmail_api:
                logger.info("Attempting lite verification for Gmail")
                try:
                    token_verified = verify_google_token(access_token, username)
                    if token_verified:
                        logger.info("Gmail OAuth token verified via REST API")
                        total_time = time.time() - start_time
                        return jsonify({
                            "status": "success", 
                            "message": "Google authentication verified successfully (lite verification)",
                            "time_taken": f"{total_time:.2f} seconds",
                            "verification_method": "rest_api",
                            "is_gmail": True
                        })
                except Exception as token_error:
                    logger.warning(f"Token verification failed, falling back to IMAP: {str(token_error)}")
            
            # If both Gmail API and token verification failed, continue to IMAP (more prone to timeouts)
        
        try:
            # Set appropriate timeout based on provider
            verification_timeout = 30 if is_gmail else 20
            socket.setdefaulttimeout(verification_timeout)
            logger.info(f"Using connection timeout: {verification_timeout} seconds")
            
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # IMAP Connection
            logger.info(f"Connecting to {imap_server}")
            connection_start = time.time()
            
            try:
                mail = imaplib.IMAP4_SSL(imap_server, DEFAULT_IMAP_PORT, ssl_context=context)
                logger.info(f"IMAP connection established in {time.time() - connection_start:.2f} seconds")
            except socket.timeout:
                logger.error(f"IMAP connection timeout after {time.time() - connection_start:.2f} seconds")
                
                # Special handling for Gmail timeout
                if is_gmail and auth_method == 'oauth':
                    try:
                        token_verified = verify_google_token(access_token, username)
                        if token_verified:
                            logger.info("Gmail OAuth token verified via REST API after IMAP timeout")
                            return jsonify({
                                "status": "success", 
                                "message": "Google authentication verified successfully. IMAP connection timed out but your credentials are valid.",
                                "time_taken": f"{time.time() - start_time:.2f} seconds",
                                "verification_method": "rest_api",
                                "is_gmail": True
                            })
                    except Exception as token_error:
                        logger.error(f"REST API verification failed after IMAP timeout: {str(token_error)}")
                
                return jsonify({
                    "status": "error", 
                    "message": f"Connection to {imap_server} timed out after {verification_timeout} seconds. Please try again or check your network connection.",
                    "is_gmail": is_gmail
                })
            except socket.gaierror as ge:
                logger.error(f"IMAP address resolution error: {str(ge)}")
                return jsonify({
                    "status": "error", 
                    "message": f"Could not resolve server address '{imap_server}'. Please check the server name.",
                    "is_gmail": is_gmail
                })
            
            # Authentication based on method
            auth_start = time.time()
            try:
                if auth_method == 'oauth':
                    logger.info("Attempting OAuth2 authentication")
                    
                    # Special handling for Gmail
                    if is_gmail:
                        logger.info("Using Gmail-specific authentication approach")
                        try:
                            # Close existing connection if any
                            try:
                                mail.shutdown()
                            except:
                                pass
                                
                            # Create new connection with our improved method
                            new_mail = imaplib.IMAP4_SSL('imap.gmail.com', 993, timeout=30)
                            
                            # Prepare auth string
                            auth_string = f'user={username}\1auth=Bearer {access_token}\1\1'
                            auth_bytes = auth_string.encode('utf-8')
                            encoded_auth = base64.b64encode(auth_bytes).decode('utf-8')
                            
                            # Authenticate
                            new_mail._simple_command('AUTHENTICATE', 'XOAUTH2', encoded_auth)
                            
                            # Copy authenticated state to original mail object
                            for attr in ['_cmd', '_tls_established', 'sock', 'file', 'state', '_mesg']:
                                if hasattr(new_mail, attr):
                                    setattr(mail, attr, getattr(new_mail, attr))
                            
                            logger.info("Gmail OAuth2 authentication successful")
                        except Exception as e:
                            logger.error(f"Gmail-specific authentication failed: {str(e)}")
                            raise ValueError("Gmail authentication failed. Please try again or use password authentication.")
                    else:
                        # Standard OAuth for non-Gmail providers
                        authenticate_oauth2(mail, username, access_token)
                else:
                    # Traditional password authentication
                    logger.info("Attempting password authentication")
                    mail.login(username, password)
                    
                logger.info(f"Authentication successful in {time.time() - auth_start:.2f} seconds")
                
                # Verify capabilities (especially for OAuth)
                if auth_method == 'oauth':
                    try:
                        status, caps = mail.capability()
                        if status == 'OK':
                            logger.info(f"Server capabilities: {caps}")
                            if b'AUTH=XOAUTH2' not in caps and is_gmail:
                                logger.warning("Server doesn't advertise XOAUTH2 capability but we authenticated anyway")
                    except Exception as cap_error:
                        logger.warning(f"Could not check server capabilities: {str(cap_error)}")
                
                # Test folder listing
                test_start = time.time()
                try:
                    status, folders = mail.list()
                    if status != 'OK':
                        logger.warning(f"Folder listing failed: {folders}")
                        raise ValueError("Could not list folders - authentication may be limited")
                    logger.info(f"Folder listing successful in {time.time() - test_start:.2f} seconds")
                except Exception as test_error:
                    logger.warning(f"Folder listing test failed: {str(test_error)}")
                    # Don't fail verification for this - just log it
                
                # Connection successful
                logger.info(f"Connection fully verified for {username}")
                mail.logout()
                
                total_time = time.time() - start_time
                logger.info(f"Verification completed in {total_time:.2f} seconds")
                
                return jsonify({
                    "status": "success", 
                    "message": "Connection verified successfully",
                    "time_taken": f"{total_time:.2f} seconds",
                    "verification_method": "imap",
                    "is_gmail": is_gmail
                })
                
            except imaplib.IMAP4.error as imap_error:
                logger.error(f"IMAP authentication error: {str(imap_error)}")
                error_message = str(imap_error)
                
                # Special handling for Gmail errors
                if is_gmail:
                    if "Invalid credentials" in error_message:
                        error_message = "Invalid Google OAuth token. Please sign in again."
                    elif "AUTHENTICATE" in error_message:
                        error_message = "Gmail authentication failed. Make sure IMAP is enabled in your Gmail settings."
                
                return jsonify({
                    "status": "error", 
                    "message": f"Authentication failed: {error_message}",
                    "details": "For Gmail, ensure IMAP is enabled in settings (Settings → Forwarding and POP/IMAP)",
                    "is_gmail": is_gmail,
                    "requires_reauth": "AUTHENTICATE" in error_message
                })
            except socket.timeout:
                logger.error(f"Authentication timeout after {time.time() - auth_start:.2f} seconds")
                
                # Special handling for Gmail timeout
                if is_gmail and auth_method == 'oauth':
                    try:
                        token_verified = verify_google_token(access_token, username)
                        if token_verified:
                            logger.info("Gmail OAuth token verified via REST API after auth timeout")
                            return jsonify({
                                "status": "success", 
                                "message": "Google authentication verified successfully. IMAP authentication timed out but your credentials are valid.",
                                "time_taken": f"{time.time() - start_time:.2f} seconds",
                                "verification_method": "rest_api",
                                "is_gmail": True
                            })
                    except Exception as token_error:
                        logger.error(f"REST API verification failed after auth timeout: {str(token_error)}")
                
                return jsonify({
                    "status": "error", 
                    "message": f"Authentication timed out after {verification_timeout} seconds. Try again later.",
                    "is_gmail": is_gmail
                })
        
        except Exception as connection_error:
            logger.error(f"Connection error: {str(connection_error)}", exc_info=True)
            
            # Try alternative verification for Gmail with OAuth
            if is_gmail and auth_method == 'oauth' and "timed out" in str(connection_error).lower():
                try:
                    token_verified = verify_google_token(access_token, username)
                    if token_verified:
                        logger.info("Gmail OAuth token verified via REST API after connection error")
                        return jsonify({
                            "status": "success", 
                            "message": "Google authentication verified successfully, but IMAP connection had issues. You may still be able to use the service.",
                            "time_taken": f"{time.time() - start_time:.2f} seconds",
                            "verification_method": "rest_api",
                            "is_gmail": True
                        })
                except Exception as token_error:
                    logger.error(f"REST API verification failed after connection error: {str(token_error)}")
            
            # Provide better error messages
            error_message = str(connection_error)
            if "timed out" in error_message.lower():
                message = f"Connection timed out. Server may be busy or unreachable."
            elif "certificate" in error_message.lower():
                message = f"SSL certificate error. The server's security certificate could not be verified."
            elif "authenticate" in error_message.lower():
                message = f"Authentication failed. Please check your credentials."
            else:
                message = error_message
                
            return jsonify({
                "status": "error", 
                "message": message,
                "details": error_message,
                "is_gmail": is_gmail,
                "requires_reauth": "authenticate" in error_message.lower()
            })
    
    except Exception as e:
        logger.error(f"Error processing verification request: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error", 
            "message": f"An unexpected error occurred: {str(e)}",
            "is_gmail": 'imap_server' in locals() and 'gmail.com' in str(imap_server).lower()
        })
        
def verify_google_token(access_token, expected_email=None):
    """Verify a Google access token using the tokeninfo endpoint
    Returns True if valid, False otherwise"""
    import json
    import urllib.request
    
    if not access_token:
        logger.error("Cannot verify empty access token")
        return False
    
    try:
        logger.info("Verifying Google token via REST API")
        # Use the tokeninfo endpoint to validate the token
        token_url = f"https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={access_token}"
        req = urllib.request.Request(token_url)
        
        try:
            # Set a short timeout for this request
            response = urllib.request.urlopen(req, timeout=10)
            token_data = json.loads(response.read().decode('utf-8'))
            
            # Check if the token is valid
            if 'error_description' in token_data:
                logger.warning(f"Token validation failed: {token_data['error_description']}")
                return False
            
            # If expected_email is provided, verify it matches
            if expected_email and 'email' in token_data:
                if token_data['email'].lower() != expected_email.lower():
                    logger.warning(f"Token email mismatch: {token_data['email']} != {expected_email}")
                    return False
                
            logger.info(f"Google token successfully verified for {token_data.get('email', 'unknown user')}")
            return True
            
        except urllib.error.HTTPError as http_err:
            logger.error(f"HTTP error during token verification: {http_err.code} - {http_err.reason}")
            return False
        except urllib.error.URLError as url_err:
            logger.error(f"URL error during token verification: {url_err.reason}")
            return False
        except socket.timeout:
            logger.error("Timeout while connecting to Google token verification service")
            return False
    
    except Exception as e:
        logger.error(f"Error verifying Google token: {str(e)}", exc_info=True)
        return False

@app.route('/get_folders', methods=['POST'])
def get_folders():
    """Get list of folders with message counts and sizes"""
    start_time = time.time()
    data = request.json
    
    # Check if we should use the Gmail API
    use_gmail_api = False
    try:
        # Only import if needed to avoid dependency issues
        import gmail_api_helper
        use_gmail_api = True
    except ImportError:
        use_gmail_api = False
    
    # Determine authentication method
    auth_method = data.get('auth_method', 'password')
    
    # Get IMAP server from input
    imap_server = data.get('imap_server')
    if not imap_server:
        return jsonify({"status": "error", "message": "IMAP server is required"})
    
    # Handle OAuth authentication
    if auth_method == 'oauth':
        # Get credentials from session
        if 'jwt_token' in session and 'user_email' in session:
            username = session.get('user_email', '')
            token = session.get('jwt_token', {})
            access_token = token.get('access_token', '')
            
            # Try to use stored IMAP server if available
            if 'imap_server' in session and not imap_server:
                imap_server = session['imap_server']
                
            if not access_token:
                return jsonify({"status": "error", "message": "No active OAuth session found"})
        else:
            return jsonify({"status": "error", "message": "No active OAuth session found"})
        
        logger.info(f"Getting folders with Auth0 OAuth for {username} on {imap_server}")
    else:
        # Traditional password authentication
        username = data['username']
        password = data['password']
        logger.info(f"Getting folders with password for {username} on {imap_server}")
    # Set up more verbose debugging for development
    if app.debug:
        mail_logger = logging.getLogger('imaplib')
        mail_logger.setLevel(logging.DEBUG)
    
    # Check if we should use the Gmail API for Gmail accounts
    is_gmail = imap_server and 'gmail' in imap_server.lower()
    if is_gmail and auth_method == 'oauth' and use_gmail_api:
        try:
            logger.info("Using Gmail API to get folders")
            # Get folders using the Gmail API
            folders_result, error_message = gmail_api_helper.get_gmail_folders(access_token)
            
            if error_message:
                logger.error(f"Error getting Gmail folders: {error_message}")
                return jsonify({
                    "status": "error",
                    "message": f"Error getting Gmail folders: {error_message}"
                })
                
            total_time = time.time() - start_time
            logger.info(f"Retrieved {len(folders_result)} Gmail folders via API in {total_time:.2f} seconds")
            
            return jsonify({
                "status": "success",
                "folders": folders_result,
                "totalMessages": sum(folder.get('messageCount', 0) for folder in folders_result),
                "totalSize": sum(folder.get('size', 0) for folder in folders_result),
                "totalSizeFormatted": format_size(sum(folder.get('size', 0) for folder in folders_result)),
                "time_taken": f"{total_time:.2f} seconds",
                "method": "gmail_api"
            })
        except Exception as api_error:
            logger.error(f"Gmail API error: {str(api_error)}")
            logger.info("Falling back to IMAP method")
            # Fall through to IMAP method below
    
    try:
        # IMAP method for non-Gmail or if Gmail API failed
        logger.info(f"Using IMAP to get folders from {imap_server}")
        
        # Set socket timeout
        socket.setdefaulttimeout(CONNECTION_TIMEOUT)
        
        # Create SSL context with verification options
        context = ssl.create_default_context()
        
        # Disable certificate verification for development/testing
        # WARNING: In production, you should use proper certificate verification!
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # IMAP Connection
        logger.info(f"Connecting to {imap_server}")
        mail = imaplib.IMAP4_SSL(imap_server, DEFAULT_IMAP_PORT, ssl_context=context)
        
        # Authentication based on method
        if auth_method == 'oauth':
            # Use our helper function for OAuth2 authentication
            authenticate_oauth2(mail, username, access_token)
        else:
            # Traditional password authentication
            mail.login(username, password)
        
        # Get list of folders
        status, folder_list = mail.list()
        
        logger.info(f"Received folder list status: {status}, count: {len(folder_list) if folder_list else 0}")
        
        # Always log folder details in debug mode for troubleshooting
        if folder_list:
            for i, f in enumerate(folder_list):
                try:
                    decoded = f.decode('utf-8', errors='ignore')
                    logger.debug(f"Folder {i}: {f}")
                    logger.debug(f"Decoded: {decoded}")
                    
                    # Try to extract parts for analysis
                    parts_by_space = decoded.split()
                    parts_by_quotes = decoded.split('"')
                    
                    logger.debug(f"Space-separated parts: {parts_by_space}")
                    logger.debug(f"Quote-separated parts: {parts_by_quotes}")
                    
                    # Examine typical positions where folder names appear
                    if len(parts_by_quotes) > 1:
                        logger.debug(f"Potential folder name (quote method): {parts_by_quotes[-2]}")
                    
                    if len(parts_by_space) >= 3:
                        logger.debug(f"Potential folder name (space method): {parts_by_space[-1]}")
                except Exception as e:
                    logger.debug(f"Error analyzing folder {i}: {str(e)}")
        
        folders = []
        total_messages = 0
        total_size = 0
        
        if status != 'OK':
            mail.logout()
            return jsonify({
                "status": "error", 
                "message": "Failed to retrieve folder list"
            })
        
        # Parse folder list and get stats for each
        for folder_info in folder_list:
            if not folder_info:
                continue
                
            # Parse folder name from response
            # The response can be in various formats depending on the mail server
            # Common formats include: 
            # - b'(\\HasNoChildren) "/" "INBOX"'
            # - b'(\\HasNoChildren) "/" {13}\r\n[Gmail]/Sent'  (Gmail might use literal syntax)
            
            try:
                # First try to decode the entire response
                decoded_info = folder_info.decode('utf-8', errors='ignore')
                if app.debug:
                    logger.debug(f"Processing folder info: {decoded_info}")
                
                # Extract the folder name - universal approach based on Hostinger format
                folder_name = None
                
                # Hostinger/mailhostbox format, based on the working code you shared
                # This is the most reliable approach for these providers
                parts = decoded_info.split('"')
                if len(parts) > 1:
                    try:
                        # Try to get the last quoted string that's not empty
                        for i in range(len(parts)-1, 0, -1):
                            if parts[i].strip() and parts[i] != '/':
                                folder_name = parts[i]
                                if app.debug:
                                    logger.debug(f"Found folder name in quotes: {folder_name}")
                                break
                    except Exception:
                        pass
                
                # If the above didn't work, try other methods
                if not folder_name or folder_name == '/' or not folder_name.strip():
                    # Try the exact format that works with Hostinger
                    try:
                        folder_parts = decoded_info.split('"')
                        folder_name = folder_parts[-2]
                        if app.debug:
                            logger.debug(f"Used Hostinger-specific extraction: {folder_name}")
                    except Exception:
                        # If still not working, try space-based splitting
                        try:
                            space_parts = decoded_info.split()
                            folder_name = space_parts[-1].strip('"')
                            if app.debug:
                                logger.debug(f"Used space-based extraction: {folder_name}")
                        except Exception:
                            pass
                
                # Fallback if the split method didn't work
                if not folder_name or not folder_name.strip():
                    # Method 2: Try to extract from literal format {n}\r\nName
                    if '{' in decoded_info and '}' in decoded_info:
                        parts = decoded_info.split('}')
                        if len(parts) > 1:
                            raw_name = parts[1].strip()
                            if raw_name.startswith('\r\n'):
                                raw_name = raw_name[2:]
                            folder_name = raw_name
                            if app.debug:
                                logger.debug(f"Extracted folder name using literal syntax: {folder_name}")
                    
                    # Method 3: Try to extract after separator
                    elif ' "/" ' in decoded_info:
                        parts = decoded_info.split(' "/" ')
                        if len(parts) > 1:
                            raw_name = parts[1].strip().strip('"')
                            folder_name = raw_name
                            if app.debug:
                                logger.debug(f"Extracted folder name using separator: {folder_name}")
                
                # If we couldn't extract a folder name, skip this folder
                if not folder_name:
                    if app.debug:
                        logger.debug(f"Could not extract folder name from: {decoded_info}")
                    continue
                    
            except Exception as e:
                logger.warning(f"Error parsing folder info: {str(e)}")
                continue
            
            # Universal handling for all providers
            
            # Keep the original folder name for selection (this is what IMAP requires)
            original_folder_name = folder_name
            
            # Create a display name that's more user-friendly
            # 1. If it has a path separator, show just the last part
            if '/' in folder_name:
                display_name = folder_name.split('/')[-1]
            else:
                display_name = folder_name
                
            # 2. Clean up any special characters for display
            display_name = display_name.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                
            if app.debug:
                logger.debug(f"Successfully parsed folder: '{folder_name}', display name: '{display_name}'")
            
            # Try to select the folder to get message count
            try:
                # Gmail folders might need special handling
                if app.debug:
                    logger.debug(f"Attempting to select folder: '{folder_name}'")
                    
                # Universal folder selection approach that works with most IMAP servers
                status = None
                folder_info = None
                success = False
                
                # Try different methods in sequence until one works
                selection_methods = [
                    # Method 1: Direct selection (no quotes) - works with many providers
                    lambda: mail.select(folder_name, readonly=True),
                    
                    # Method 2: With double quotes - standard approach
                    lambda: mail.select(f'"{folder_name}"', readonly=True),
                    
                    # Method 3: If folder has a path separator, try just the last part
                    lambda: mail.select(f'"{folder_name.split("/")[-1]}"', readonly=True) 
                    if '/' in folder_name else None,
                    
                    # Method 4: Try with URL encoding - helps with special characters
                    lambda: mail.select(urllib.parse.quote(folder_name), readonly=True),
                    
                    # Method 5: Try with single quotes - some servers prefer this
                    lambda: mail.select(f"'{folder_name}'", readonly=True)
                ]
                
                # Try each method in sequence
                for i, method in enumerate(selection_methods):
                    if method is None:  # Skip this method if it's not applicable
                        continue
                        
                    try:
                        status, folder_info = method()
                        if status == 'OK':
                            if app.debug:
                                logger.debug(f"Successfully selected folder using method {i+1}: {folder_name}")
                            success = True
                            break
                    except Exception as e:
                        if app.debug:
                            logger.debug(f"Error selecting folder with method {i+1}: {str(e)}")
                
                # If all methods failed, use a dummy status
                if not success:
                    status = 'NO'
                    folder_info = [b'0']
                
                message_count = 0
                size = 0
                
                if status == 'OK':
                    message_count = int(folder_info[0])
                    
                    # Get size estimate by checking a sample of messages
                    if message_count > 0:
                        # Sample up to 10 messages to estimate average size
                        sample_size = min(10, message_count)
                        sample_indices = [1]  # Start with the first message
                        
                        # Add some messages from the middle and end
                        if message_count > 1:
                            middle = message_count // 2
                            sample_indices.append(middle)
                        
                        if message_count > 2:
                            sample_indices.append(message_count)
                        
                        total_sample_size = 0
                        
                        for idx in sample_indices:
                            try:
                                status, fetch_response = mail.fetch(str(idx), '(RFC822.SIZE)')
                                if status == 'OK' and fetch_response[0]:
                                    # Extract the size from response like b'1 (RFC822.SIZE 2578)'
                                    size_match = re.search(r'RFC822\.SIZE\s+(\d+)', fetch_response[0].decode('utf-8', errors='ignore'))
                                    if size_match:
                                        total_sample_size += int(size_match.group(1))
                            except Exception as e:
                                logger.warning(f"Error getting message size for folder {folder_name}: {str(e)}")
                        
                        # Calculate average size and multiply by message count
                        if len(sample_indices) > 0:
                            avg_size = total_sample_size / len(sample_indices)
                            size = int(avg_size * message_count)
                
                # Format size
                size_formatted = format_size(size)
                
                # Add to folder list with both original name and display name
                folders.append({
                    'name': folder_name,  # Original folder name needed for IMAP commands
                    'displayName': display_name,  # User-friendly name for display
                    'messageCount': message_count,
                    'size': size,
                    'sizeFormatted': size_formatted
                })
                
                total_messages += message_count
                total_size += size
                
            except Exception as e:
                logger.warning(f"Error processing folder {folder_name}: {str(e)}")
                continue
        
        mail.logout()
        
        # Sort folders: common folders first, then alphabetically
        common_folders = ['INBOX', 'Sent', 'Drafts', 'Trash', 'Spam', 'Archive', 'Junk']
        
        def folder_sort_key(folder):
            try:
                # Use display name for sorting
                display_name = folder['displayName'] if 'displayName' in folder else folder['name']
                # Return position in common_folders list if present, otherwise a high number
                return common_folders.index(display_name)
            except ValueError:
                return len(common_folders) + 1
        
        # Sort by common folders first, then by message count (descending)
        folders.sort(key=lambda f: (folder_sort_key(f), -f['messageCount']))
        
        return jsonify({
            "status": "success",
            "folders": folders,
            "totalMessages": total_messages,
            "totalSize": total_size,
            "totalSizeFormatted": format_size(total_size),
            "time_taken": f"{(time.time() - start_time):.2f} seconds"
        })
    
    except Exception as e:
        logger.error(f"Error getting folders: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error", 
            "message": str(e)
        })

@app.route('/progress/<task_id>', methods=['GET'])
def get_progress(task_id):
    """Get progress for a specific cleanup task"""
    if task_id not in cleanup_progress:
        return jsonify({
            "status": "error",
            "message": "Task not found"
        })
    
    # Check if the task is running but hasn't advanced past 10%
    if task_id in cleanup_running_status:
        # If we're stuck in the workload estimation phase for too long, report it
        current_time = time.time()
        last_update_time = cleanup_running_status[task_id]['last_update']
        current_progress = cleanup_progress[task_id]['overall_progress']
        
        # If it's been more than 30 seconds with progress < 12% and task not completed, 
        # assume there's a stall in workload estimation
        if (current_time - last_update_time > 30 and 
            current_progress < 12 and 
            not cleanup_progress[task_id].get('completed', False)):
            
            # Add a progress increment to show it's still working
            cleanup_progress[task_id]['overall_progress'] += 0.5
            # Update the timestamp to prevent excessive increments
            cleanup_running_status[task_id]['last_update'] = current_time
    
    return jsonify({
        "status": "success",
        "progress": cleanup_progress[task_id]
    })

@app.route('/clean', methods=['POST'])
def clean_emails():
    """Start email cleanup process with progress tracking"""
    data = request.json
    folders = data.get('folders', ['INBOX'])
    
    # Get IMAP server from input
    imap_server = data.get('imap_server')
    if not imap_server:
        return jsonify({"status": "error", "message": "IMAP server is required"})
        
    # Determine authentication method
    auth_method = data.get('auth_method', 'password')
    
    # Handle OAuth authentication
    if auth_method == 'oauth':
        # Get credentials from session
        if 'jwt_token' in session and 'user_email' in session:
            username = session.get('user_email', '')
            token = session.get('jwt_token', {})
            access_token = token.get('access_token', '')
            password = None  # Not used for OAuth
            
            # Try to use stored IMAP server if available
            if 'imap_server' in session and not imap_server:
                imap_server = session['imap_server']
                
            if not access_token:
                return jsonify({"status": "error", "message": "No active OAuth session found"})
        else:
            return jsonify({"status": "error", "message": "No active OAuth session found"})
    else:
        # Traditional password authentication
        username = data['username']
        password = data['password']
        access_token = None  # Not used for password auth
    
    # Get cutoff date from user input or use default
    cutoff_date = data.get('cutoff_date')
    if not cutoff_date:
        cutoff_date = DEFAULT_CUTOFF_DATE
    
    # Generate a unique task ID
    task_id = str(uuid.uuid4())
    
    # Initialize progress tracking
    current_time = time.time()
    cleanup_progress[task_id] = {
        "overall_progress": 0,
        "current_folder": "Initializing...",
        "current_folder_progress": 0,
        "folders_completed": 0,
        "total_folders": len(folders),
        "total_emails_deleted": 0,
        "total_size_deleted": 0,
        "results": {},
        "completed": False,
        "start_time": current_time
    }
    
    # Initialize running status tracking
    cleanup_running_status[task_id] = {
        "last_update": current_time,
        "phase": "initializing"
    }
    
    # Start cleanup in a separate thread to allow progress tracking
    thread = threading.Thread(target=process_cleanup, args=(
        task_id, username, password, imap_server, folders, cutoff_date, auth_method, access_token
    ))
    thread.daemon = True
    thread.start()
    
    # Return task_id immediately for client to poll progress
    return jsonify({
        "status": "success",
        "message": "Cleanup started",
        "task_id": task_id
    })

def process_cleanup(task_id, username, password, imap_server, folders, cutoff_date, auth_method='password', access_token=None):
    """Process cleanup in a background thread with progress tracking"""
    start_time = time.time()
    
    try:
        # Set socket timeout
        socket.setdefaulttimeout(CONNECTION_TIMEOUT)
        
        # Create SSL context with verification options
        context = ssl.create_default_context()
        
        # Disable certificate verification for development/testing
        # WARNING: In production, you should use proper certificate verification!
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # IMAP Connection
        logger.info(f"Connecting to {imap_server}")
        cleanup_progress[task_id]["current_folder"] = "Connecting to server..."
        
        mail = imaplib.IMAP4_SSL(imap_server, DEFAULT_IMAP_PORT, ssl_context=context)
        
        # Authentication based on method
        if auth_method == 'oauth':
            logger.info(f"Using OAuth authentication for {username}")
            # Use our helper function for OAuth2 authentication
            authenticate_oauth2(mail, username, access_token)
        else:
            # Traditional password authentication
            logger.info(f"Using password authentication for {username}")
            mail.login(username, password)
        
        results = {}
        total_emails_deleted = 0
        total_size_deleted = 0
        
        # Update progress after connection (5%)
        cleanup_progress[task_id]["overall_progress"] = 5
        cleanup_running_status[task_id]["last_update"] = time.time()
        cleanup_running_status[task_id]["phase"] = "connected"
        
        # First pass - estimate workload by counting messages in each folder
        logger.info(f"Estimating workload for {len(folders)} folders")
        cleanup_progress[task_id]["current_folder"] = "Estimating workload..."
        cleanup_running_status[task_id]["phase"] = "estimating_workload_start"
        
        total_messages_to_process = 0
        folder_message_counts = {}
        
        # Set a timeout for the estimation phase
        estimation_start_time = time.time()
        
        for folder_idx, folder in enumerate(folders):
            try:
                # Universal folder selection approach
                status = None
                folder_info = None
                success = False
                
                # Try different methods in sequence until one works
                selection_methods = [
                    # Method 1: Direct selection (no quotes)
                    lambda: mail.select(folder, readonly=True),
                    
                    # Method 2: With double quotes
                    lambda: mail.select(f'"{folder}"', readonly=True),
                    
                    # Method 3: If folder has a path separator, try just the last part
                    lambda: mail.select(f'"{folder.split("/")[-1]}"', readonly=True) 
                    if '/' in folder else None,
                    
                    # Method 4: Try with URL encoding
                    lambda: mail.select(urllib.parse.quote(folder), readonly=True),
                    
                    # Method 5: Try with single quotes
                    lambda: mail.select(f"'{folder}'", readonly=True)
                ]
                
                # Try each method in sequence
                for i, method in enumerate(selection_methods):
                    if method is None:  # Skip this method if it's not applicable
                        continue
                        
                    try:
                        status, folder_info = method()
                        if status == 'OK':
                            if app.debug:
                                logger.debug(f"Successfully selected folder using method {i+1}: {folder}")
                            success = True
                            break
                    except Exception as e:
                        if app.debug:
                            logger.debug(f"Error selecting folder with method {i+1}: {str(e)}")
                
                # If all methods failed, use a dummy status
                if not success:
                    status = 'NO'
                    folder_info = [b'0']
                    
                if status != 'OK':
                    continue
                
                # Search for emails before the cutoff date
                search_command = f'(BEFORE "{cutoff_date}")'
                try:
                    # Add a timeout check for the estimation phase
                    current_time = time.time()
                    if current_time - estimation_start_time > 60:  # 60 seconds max for estimation
                        logger.warning(f"Estimation phase taking too long, proceeding with partial data for folder {folder}")
                        cleanup_progress[task_id]["current_folder"] = f"Workload estimation is taking longer than expected..."
                        # Force progress to 11% to avoid stuck at 10%
                        cleanup_progress[task_id]["overall_progress"] = 11
                        cleanup_running_status[task_id]["last_update"] = current_time
                        raise TimeoutError("Estimation phase timeout")
                        
                    status, messages = mail.search(None, search_command)
                except TimeoutError:
                    status = 'NO'
                    messages = [b'']
                    logger.error(f"Timeout during search for folder {folder}")
                except Exception as e:
                    status = 'NO'
                    messages = [b'']
                    logger.error(f"Error during search for folder {folder}: {str(e)}")
                
                if status == 'OK':
                    message_ids = messages[0].split()
                    folder_message_counts[folder] = len(message_ids)
                    total_messages_to_process += len(message_ids)
            
            except Exception:
                folder_message_counts[folder] = 0  # Assume zero if we couldn't check
                
            # Update progress (up to 10%)
            progress = 5 + (folder_idx + 1) / len(folders) * 5
            cleanup_progress[task_id]["overall_progress"] = progress
            cleanup_running_status[task_id]["last_update"] = time.time()
            cleanup_running_status[task_id]["phase"] = "estimating_workload"
        
        # Second pass - actually process each folder
        total_messages_processed = 0
        
        # Check if we have any messages to process
        if total_messages_to_process == 0:
            # Force progress beyond 10% to prevent frontend getting stuck
            cleanup_progress[task_id]["overall_progress"] = 11
            cleanup_running_status[task_id]["last_update"] = time.time()
            logger.info("No messages found to process, but advancing progress to prevent UI getting stuck")
            
        # Set phase to processing
        cleanup_running_status[task_id]["phase"] = "processing_start"
        
        for folder_idx, folder in enumerate(folders):
            try:
                folder_start_time = time.time()
                logger.info(f"Processing folder: {folder}")
                
                # Update progress tracker
                cleanup_progress[task_id]["current_folder"] = folder
                cleanup_progress[task_id]["current_folder_progress"] = 0
                
                # Universal folder selection approach (without readonly flag for actual processing)
                status = None
                folder_info = None
                success = False
                
                # Try different methods in sequence until one works
                selection_methods = [
                    # Method 1: Direct selection (no quotes)
                    lambda: mail.select(folder),
                    
                    # Method 2: With double quotes
                    lambda: mail.select(f'"{folder}"'),
                    
                    # Method 3: If folder has a path separator, try just the last part
                    lambda: mail.select(f'"{folder.split("/")[-1]}"') 
                    if '/' in folder else None,
                    
                    # Method 4: Try with URL encoding
                    lambda: mail.select(urllib.parse.quote(folder)),
                    
                    # Method 5: Try with single quotes
                    lambda: mail.select(f"'{folder}'")
                ]
                
                # Try each method in sequence
                for i, method in enumerate(selection_methods):
                    if method is None:  # Skip this method if it's not applicable
                        continue
                        
                    try:
                        status, folder_info = method()
                        if status == 'OK':
                            if app.debug:
                                logger.debug(f"Successfully selected folder for cleaning using method {i+1}: {folder}")
                            success = True
                            break
                    except Exception as e:
                        if app.debug:
                            logger.debug(f"Error selecting folder for cleaning with method {i+1}: {str(e)}")
                
                # If all methods failed, use a dummy status
                if not success:
                    status = 'NO'
                    folder_info = [b'0']
                    
                if status != 'OK':
                    results[folder] = {
                        "status": "error",
                        "message": "Couldn't select folder",
                        "count": 0,
                        "size": 0
                    }
                    logger.warning(f"Failed to select folder {folder}: {folder_info}")
                    
                    # Update progress
                    cleanup_progress[task_id]["folders_completed"] += 1
                    cleanup_progress[task_id]["results"][folder] = results[folder]
                    
                    continue
                
                # Search for emails before the cutoff date
                search_command = f'(BEFORE "{cutoff_date}")'
                logger.info(f"Searching emails with command: {search_command}")
                status, messages = mail.search(None, search_command)
                
                if status == 'OK':
                    message_ids = messages[0].split()
                    total_messages = len(message_ids)
                    logger.info(f"Found {total_messages} emails to delete in {folder}")
                    
                    # Calculate total size of messages to be deleted
                    folder_total_size = 0
                    
                    # Check if we found any messages
                    if message_ids:
                        # Sample to get an average size
                        sample_size = min(10, total_messages)
                        sampled_ids = []
                        
                        # Get a sample of message IDs
                        if total_messages <= 10:
                            sampled_ids = message_ids
                        else:
                            # Take some from beginning, middle, and end
                            step = total_messages // sample_size
                            for i in range(0, total_messages, step):
                                if len(sampled_ids) < sample_size:
                                    sampled_ids.append(message_ids[i])
                        
                        # Get sizes of sampled messages
                        total_sampled_size = 0
                        for mid in sampled_ids:
                            try:
                                status, fetch_response = mail.fetch(mid, '(RFC822.SIZE)')
                                if status == 'OK' and fetch_response[0]:
                                    size_match = re.search(r'RFC822\.SIZE\s+(\d+)', fetch_response[0].decode('utf-8', errors='ignore'))
                                    if size_match:
                                        total_sampled_size += int(size_match.group(1))
                            except Exception as e:
                                logger.warning(f"Error getting message size: {str(e)}")
                        
                        # Calculate average size and estimated total size
                        if len(sampled_ids) > 0:
                            avg_size = total_sampled_size / len(sampled_ids)
                            folder_total_size = int(avg_size * total_messages)
                        
                        # Process messages in batches to avoid command length limits
                        total_deleted = 0
                        
                        for i in range(0, total_messages, BATCH_SIZE):
                            batch = message_ids[i:min(i+BATCH_SIZE, total_messages)]
                            batch_size = len(batch)
                            
                            # Convert byte IDs to strings and join with commas
                            id_string = ','.join(id.decode() for id in batch)
                            
                            logger.info(f"Deleting batch of {batch_size} emails ({i+1}-{i+batch_size} of {total_messages})")
                            
                            # Mark messages as deleted
                            store_status, store_response = mail.store(id_string, '+FLAGS', '\\Deleted')
                            if store_status != 'OK':
                                logger.warning(f"Store command issue: {store_response}")
                                continue
                                
                            total_deleted += batch_size
                            total_messages_processed += batch_size
                            
                            # Update folder progress
                            folder_progress = (i + batch_size) / total_messages * 100
                            cleanup_progress[task_id]["current_folder_progress"] = folder_progress
                            
                            # Update overall progress (10-95%) with smoother increments
                            if total_messages_to_process > 0:
                                # Calculate raw progress
                                raw_progress = 10 + (total_messages_processed / total_messages_to_process * 85)
                                
                                # Get current progress
                                current = cleanup_progress[task_id]["overall_progress"]
                                
                                # Smoothing: only update if progress increases by at least 0.5% 
                                # or we're at the beginning/end stages
                                if (raw_progress - current >= 0.5) or (current < 12) or (raw_progress > 90):
                                    cleanup_progress[task_id]["overall_progress"] = min(95, raw_progress)
                                    cleanup_running_status[task_id]["last_update"] = time.time()
                                    cleanup_running_status[task_id]["phase"] = "processing_folders"
                            
                            # Update running totals for real-time stats
                            cleanup_progress[task_id]["total_emails_deleted"] = total_emails_deleted + total_deleted
                            cleanup_progress[task_id]["total_size_deleted"] = total_size_deleted + folder_total_size
                            
                            # Give some breathing room for large operations
                            if total_messages > 1000 and i % 1000 == 0 and i > 0:
                                logger.info(f"Processed {i} emails, pausing briefly...")
                                time.sleep(0.5)  # Small pause to prevent server timeouts
                        
                        # Expunge to permanently remove the messages
                        logger.info(f"Expunging {total_deleted} emails from {folder}")
                        mail.expunge()
                        
                        results[folder] = {
                            "status": "success",
                            "message": f"Deleted {total_deleted} emails",
                            "count": total_deleted,
                            "size": folder_total_size
                        }
                        
                        total_emails_deleted += total_deleted
                        total_size_deleted += folder_total_size
                    else:
                        results[folder] = {
                            "status": "success",
                            "message": "No emails found before cutoff date",
                            "count": 0,
                            "size": 0
                        }
                else:
                    results[folder] = {
                        "status": "error",
                        "message": f"Error searching for emails: {messages}",
                        "count": 0,
                        "size": 0
                    }
                
                folder_time = time.time() - folder_start_time
                logger.info(f"Finished processing {folder} in {folder_time:.2f} seconds")
                
                # Update progress tracker for this folder
                cleanup_progress[task_id]["folders_completed"] += 1
                cleanup_progress[task_id]["results"][folder] = results[folder]
                    
            except Exception as e:
                logger.error(f"Error processing folder {folder}: {str(e)}", exc_info=True)
                results[folder] = {
                    "status": "error",
                    "message": str(e),
                    "count": 0,
                    "size": 0
                }
                
                # Update progress even on error
                cleanup_progress[task_id]["folders_completed"] += 1
                cleanup_progress[task_id]["results"][folder] = results[folder]
        
        mail.logout()
        total_time = time.time() - start_time
        logger.info(f"Completed email cleanup. Deleted {total_emails_deleted} emails in {total_time:.2f} seconds")
        
        # Finalize progress tracker
        cleanup_progress[task_id]["overall_progress"] = 100
        cleanup_progress[task_id]["current_folder"] = "Complete"
        cleanup_progress[task_id]["current_folder_progress"] = 100
        cleanup_progress[task_id]["total_emails_deleted"] = total_emails_deleted
        cleanup_progress[task_id]["total_size_deleted"] = total_size_deleted
        cleanup_progress[task_id]["completed"] = True
        cleanup_progress[task_id]["time_taken"] = f"{total_time:.2f} seconds"
        cleanup_progress[task_id]["results"] = results
        
        # Update running status to completed
        cleanup_running_status[task_id]["last_update"] = time.time()
        cleanup_running_status[task_id]["phase"] = "completed"
        
        # Keep results for a limited time (could add cleanup routine)
        
    except Exception as e:
        logger.error(f"Error during email cleanup: {str(e)}", exc_info=True)
        
        # Update progress with error
        cleanup_progress[task_id]["current_folder"] = "Error"
        cleanup_progress[task_id]["error"] = str(e)
        cleanup_progress[task_id]["completed"] = True
        
        # Update running status to error
        cleanup_running_status[task_id]["last_update"] = time.time()
        cleanup_running_status[task_id]["phase"] = "error"

# Alternative approach for Gmail authentication that relies less on the IMAP library internals
def gmail_oauth2_login(username, access_token):
    """Create a new Gmail IMAP connection with OAuth2 authentication"""
    # Note: base64, imaplib, ssl are imported at the module level
    import signal
    
    # Make sure username is a string
    if isinstance(username, bytes):
        username = username.decode('utf-8')
    
    # Ensure access_token is valid
    if not access_token:
        logger.error("OAuth access token is missing or empty")
        raise ValueError("OAuth access token is required for authentication")
    
    logger.info(f"Creating new Gmail connection for {username}")
    
    # Create a new connection with a 30-second timeout
    logger.info("Setting up SSL context for Gmail connection")
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    # Define timeout handler
    def timeout_handler(signum, frame):
        logger.error("Gmail authentication operation timed out")
        raise TimeoutError("Operation timed out while authenticating with Gmail")

    try:
        # Set an overall timeout for the entire operation (45 seconds)
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(45)  # 45 seconds timeout for entire auth process
        
        # Connect to Gmail IMAP server
        logger.info("Connecting to imap.gmail.com")
        mail = imaplib.IMAP4_SSL('imap.gmail.com', 993, ssl_context=context, timeout=30)
        
        # Create the authentication string
        auth_string = f'user={username}\1auth=Bearer {access_token}\1\1'
        auth_bytes = auth_string.encode('utf-8')
        encoded_auth = base64.b64encode(auth_bytes)
        
        # Perform OAuth2 authentication
        logger.info("Sending AUTHENTICATE XOAUTH2 command")
        typ, data = mail._simple_command('AUTHENTICATE', 'XOAUTH2')
        logger.info(f"Initial AUTHENTICATE response: {typ}")
        
        # Wait for continuation response
        if typ != 'OK' and not typ.startswith('+'):
            logger.info(f"Sending credentials (length: {len(encoded_auth)})")
            mail.send(encoded_auth + b'\r\n')
            
            # Check final response
            typ, data = mail._get_response()
            logger.info(f"Final AUTHENTICATE response: {typ}")
            
            if typ != 'OK':
                error = data[0].decode('utf-8') if data and data[0] else "Unknown authentication error"
                logger.error(f"Gmail authentication failed: {error}")
                raise imaplib.IMAP4.error(f"Authentication failed: {error}")
        
        # Cancel the alarm since we completed successfully
        signal.alarm(0)
        logger.info("Gmail OAuth2 authentication successful")
        return mail
        
    except TimeoutError as te:
        # This will be triggered by our signal handler
        logger.error(f"Gmail authentication timed out: {str(te)}")
        raise ValueError("Connection to Gmail timed out. Try again or use password authentication instead.")
    except (socket.timeout, socket.gaierror) as e:
        logger.error(f"Connection error with Gmail: {str(e)}")
        raise ValueError(f"Could not connect to Gmail's IMAP server: {str(e)}")
    except imaplib.IMAP4.error as e:
        logger.error(f"IMAP protocol error: {str(e)}")
        raise ValueError(f"Gmail authentication failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error during Gmail connection: {str(e)}")
        raise ValueError(f"Error connecting to Gmail: {str(e)}")
    finally:
        # Always make sure to cancel the alarm
        try:
            signal.alarm(0)
        except:
            pass


# Helper function to perform XOAUTH2 authentication with retries
def authenticate_oauth2(mail, username, access_token, max_retries=1):
    """Authenticate with IMAP server using XOAUTH2 with Gmail-specific handling"""
    # Note: base64 and imaplib are imported at the module level
    import time
    import signal
    
    # Identify server type
    server_type = getattr(mail, '_host', '').lower()
    is_gmail = 'gmail' in server_type
    
    # For Gmail, always use our special handling
    if is_gmail:
        try:
            # Close existing connection if it exists
            try:
                if getattr(mail, '_tls_established', False):
                    mail.shutdown()
            except:
                pass
                
            # Create new authenticated connection
            new_mail = imaplib.IMAP4_SSL('imap.gmail.com', 993, timeout=30)
            
            # Prepare auth string
            auth_string = f'user={username}\1auth=Bearer {access_token}\1\1'
            auth_bytes = auth_string.encode('utf-8')
            encoded_auth = base64.b64encode(auth_bytes).decode('utf-8')
            
            # Authenticate
            new_mail._simple_command('AUTHENTICATE', 'XOAUTH2', encoded_auth)
            
            # Copy authenticated state to original mail object
            for attr in ['_cmd', '_tls_established', 'sock', 'file', 'state', '_mesg']:
                if hasattr(new_mail, attr):
                    setattr(mail, attr, getattr(new_mail, attr))
                    
            logger.info("Gmail OAuth2 authentication successful")
            return
            
        except Exception as e:
            logger.error(f"Gmail-specific authentication failed: {str(e)}")
            raise ValueError("Gmail authentication failed. Please try again or use password authentication.")
    
    # Standard XOAUTH2 for non-Gmail providers
    try:
        auth_string = f'user={username}\1auth=Bearer {access_token}\1\1'
        auth_bytes = auth_string.encode('utf-8')
        encoded_auth = base64.b64encode(auth_bytes)
        
        mail._simple_command('AUTHENTICATE', 'XOAUTH2')
        mail.send(encoded_auth + b'\r\n')
        mail._check_response()
        logger.info("XOAUTH2 authentication successful")
        
    except imaplib.IMAP4.error as e:
        error_msg = str(e)
        if "invalid_grant" in error_msg.lower() or "invalid_token" in error_msg.lower():
            logger.warning("OAuth token appears to be expired or invalid")
            raise ValueError("Your authentication has expired. Please sign in again.")
        else:
            logger.error(f"XOAUTH2 authentication failed: {error_msg}")
            raise ValueError(f"Authentication failed: {error_msg}")


def format_size(size_bytes):
    """Format size in bytes to human-readable format"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes/1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes/(1024*1024):.1f} MB"
    else:
        return f"{size_bytes/(1024*1024*1024):.1f} GB"

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Server error: {str(error)}")
    return jsonify({
        "status": "error",
        "message": "Internal server error"
    }), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "status": "error",
        "message": "Endpoint not found"
    }), 404

if __name__ == '__main__':
    # For Railway and other PaaS platforms, get port from environment
    port = int(os.environ.get('PORT', 5050))
    
    # Enable debug mode only locally, not in production
    debug_mode = os.environ.get('RAILWAY_ENVIRONMENT', None) is None
    
    # Make the app accessible on all network interfaces
    
    # Configure logging level based on environment
    logging_level = logging.WARNING if is_production else logging.INFO
    logger.setLevel(logging_level)
    
    # Run the app
    try:
        logger.info(f"Starting application on port {port}")
        app.run(host='0.0.0.0', port=port, debug=debug_mode)

    except Exception as e:
        logger.critical(f"Failed to start application: {str(e)}")
        raise



