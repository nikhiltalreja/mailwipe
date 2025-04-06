# app.py - with enhanced Gmail API integration and refactoring
import base64
import email.utils
import json
import logging
import logging.handlers
import os
import platform
import psutil
import re
import secrets
import socket
import ssl
import sys
import threading
import time
import urllib.parse
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone # Added timezone

from authlib.integrations.flask_client import OAuth
from flask import (Flask, jsonify, redirect, render_template, request, session,
                   url_for)

# Import Gmail helper and check availability
try:
    import gmail_api_helper
    GMAIL_HELPER_AVAILABLE = True
    logging.info("gmail_api_helper loaded successfully.")
except ImportError as e:
    gmail_api_helper = None # Make it explicit it's not available
    GMAIL_HELPER_AVAILABLE = False
    logging.warning(f"Could not import gmail_api_helper: {e}. Gmail API features will be disabled.")

# Standard library imports required by functions originally here
import imaplib # Still needed for non-Gmail and fallback

# Import OAuth configuration - prioritize environment variables over config file
AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN")
AUTH0_CLIENT_ID = os.environ.get("AUTH0_CLIENT_ID")
AUTH0_CLIENT_SECRET = os.environ.get("AUTH0_CLIENT_SECRET")
AUTH0_CALLBACK_URL = os.environ.get("AUTH0_CALLBACK_URL")

DEFAULT_IMAP_SERVERS_DEFAULT = {
    "gmail.com": "imap.gmail.com", "googlemail.com": "imap.gmail.com",
    "outlook.com": "outlook.office365.com", "hotmail.com": "outlook.office365.com",
    "live.com": "outlook.office365.com", "yahoo.com": "imap.mail.yahoo.com",
    "ymail.com": "imap.mail.yahoo.com", "aol.com": "imap.aol.com"
}
DEFAULT_IMAP_SERVERS = DEFAULT_IMAP_SERVERS_DEFAULT

# If environment variables are not set, try to import from config file
if not all([AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET, AUTH0_CALLBACK_URL]):
    try:
        from oauth_config import (AUTH0_DOMAIN as config_domain,
                                  AUTH0_CLIENT_ID as config_client_id,
                                  AUTH0_CLIENT_SECRET as config_secret,
                                  AUTH0_CALLBACK_URL as config_callback,
                                  DEFAULT_IMAP_SERVERS as config_servers)

        # Only use config values if env vars are not set
        AUTH0_DOMAIN = AUTH0_DOMAIN or config_domain
        AUTH0_CLIENT_ID = AUTH0_CLIENT_ID or config_client_id
        AUTH0_CLIENT_SECRET = AUTH0_CLIENT_SECRET or config_secret
        AUTH0_CALLBACK_URL = AUTH0_CALLBACK_URL or config_callback
        DEFAULT_IMAP_SERVERS = config_servers or DEFAULT_IMAP_SERVERS_DEFAULT

    except ImportError:
        # Fallback defaults if neither env vars nor config file are available
        if not AUTH0_DOMAIN: AUTH0_DOMAIN = "your-tenant.auth0.com"
        if not AUTH0_CLIENT_ID: AUTH0_CLIENT_ID = "your-client-id"
        if not AUTH0_CLIENT_SECRET: AUTH0_CLIENT_SECRET = "your-client-secret"
        if not AUTH0_CALLBACK_URL: AUTH0_CALLBACK_URL = "http://localhost:5050/auth/callback"
        # Default IMAP servers already set above

else:
    # If we're using env vars, try to get DEFAULT_IMAP_SERVERS from config if it exists
    try:
        from oauth_config import DEFAULT_IMAP_SERVERS as config_servers
        DEFAULT_IMAP_SERVERS = config_servers or DEFAULT_IMAP_SERVERS_DEFAULT
    except ImportError:
        pass # Keep the default if oauth_config doesn't exist

# --- Flask App Setup ---
app = Flask(__name__)

# Configure root logger first
logger = logging.getLogger(__name__)

# Enhanced session configuration for Railway
if 'SECRET_KEY' not in os.environ and not os.environ.get('RAILWAY_ENVIRONMENT'):
    logger.warning("SECRET_KEY not set - generating temporary key for development")
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
    SESSION_COOKIE_DOMAIN='.railway.app',
    SERVER_NAME='web-production-99c5.up.railway.app',
    # Additional session security
    SESSION_REFRESH_EACH_REQUEST=True,
    SESSION_COOKIE_NAME='mailwipe_session',
    SESSION_COOKIE_PATH='/',
    SESSION_TYPE='filesystem'
)

# Verify session config
logger.info(f"Session cookie domain: {app.config['SESSION_COOKIE_DOMAIN']}")
logger.info(f"Session cookie secure: {app.config['SESSION_COOKIE_SECURE']}")

# --- Auth0 Client Setup ---
oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=f'https://{AUTH0_DOMAIN}',
    access_token_url=f'https://{AUTH0_DOMAIN}/oauth/token',
    authorize_url=f'https://{AUTH0_DOMAIN}/authorize',
    server_metadata_url=f'https://{AUTH0_DOMAIN}/.well-known/openid-configuration',
    client_kwargs={
        # Crucial: Request 'offline_access' for refresh tokens if needed long-term
        # Add 'https://mail.google.com/' for Gmail API access
        'scope': 'openid profile email https://mail.google.com/',
        'token_endpoint_auth_method': 'client_secret_post',
        # 'audience': f'https://{AUTH0_DOMAIN}/api/v2/' # Usually needed for Auth0 Management API, not generally for external APIs like Google. Remove if causing issues.
    },
    # access_token_params={'audience': f'https://{AUTH0_DOMAIN}/userinfo'}, # Send audience for userinfo if needed, test this.
)


# --- Logging Configuration ---
log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
numeric_level = getattr(logging, log_level, logging.INFO)

# Log rotation
log_handler = logging.handlers.RotatingFileHandler(
    filename='emailwipe.log', maxBytes=5*1024*1024, backupCount=5 # Increased size/count
)
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s') # Added threadName
log_handler.setFormatter(log_formatter)

# Circular buffer for recent logs view
class CircularLogBuffer(logging.Handler):
    def __init__(self, capacity=250): # Increased capacity
        logging.Handler.__init__(self)
        self.capacity = capacity
        self.buffer = []
        self.formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(name)s] %(message)s') # Simpler format for buffer view
        self._lock = threading.Lock() # Thread safety

    def emit(self, record):
        log_entry = {
            "timestamp": self.formatTime(record, "%Y-%m-%d %H:%M:%S"), # Custom time format
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name
        }
        with self._lock:
            self.buffer.append(log_entry)
            if len(self.buffer) > self.capacity:
                self.buffer.pop(0)

    def get_logs(self):
        with self._lock:
            return list(self.buffer) # Return a copy

log_buffer = CircularLogBuffer(capacity=250)
log_buffer.setLevel(logging.INFO) # Capture INFO and above

# Configure root logger
logging.basicConfig(level=numeric_level,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(threadName)s - %(message)s', # Consistent format
                    handlers=[log_handler, log_buffer, logging.StreamHandler(sys.stdout)]) # Also log to stdout for platforms like Railway

logger = logging.getLogger(__name__) # Use __name__ for module-level logger

# Log startup info
logger.info(f"Starting EmailWipe - Python {sys.version}")
logger.info(f"Log level set to: {log_level}")
logger.info(f"Auth0 Domain: {AUTH0_DOMAIN}")
logger.info(f"Callback URL: {AUTH0_CALLBACK_URL}")
logger.info(f"Gmail Helper Available: {GMAIL_HELPER_AVAILABLE}")

# --- Global Exception Handling ---
def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    logger.critical("UNCAUGHT EXCEPTION:", exc_info=(exc_type, exc_value, exc_traceback))

sys.excepthook = handle_exception

# --- Constants and Globals ---
DEFAULT_CUTOFF_DATE = '01-Jan-2021' # Standard IMAP format
DEFAULT_IMAP_PORT = 993
BATCH_SIZE = 100 # For IMAP batching
CONNECTION_TIMEOUT = 30  # Increased default timeout (seconds)

# In-memory storage for progress (consider alternatives for scalability)
cleanup_progress = {}
cleanup_running_status = {}
progress_lock = threading.Lock() # Lock for thread-safe access to progress dicts


# --- Basic Routes ---
@app.route('/')
def index():
    demo_mode = request.args.get('demo', 'false').lower() == 'true'
    return render_template('index.html', demo_mode=demo_mode, debug=app.debug)

@app.route('/demo')
def demo():
    return redirect('/?demo=true')

@app.route('/health')
def health_check():
    """Extended health check endpoint"""
    try:
        process = psutil.Process()
        memory_info = process.memory_info()
        env_vars = {
            'SECRET_KEY_SET': 'SECRET_KEY' in os.environ,
            'AUTH0_VARS_SET': all(k in os.environ for k in ['AUTH0_DOMAIN', 'AUTH0_CLIENT_ID', 'AUTH0_CLIENT_SECRET']),
        }
        response_data = {
            "status": "ok", "version": "1.2", "timestamp": datetime.now().isoformat(),
            "auth_configured": bool(AUTH0_DOMAIN and AUTH0_CLIENT_ID and AUTH0_CLIENT_SECRET),
            "python_version": platform.python_version(),
            "memory_usage_mb": round(memory_info.rss / (1024 * 1024), 2),
            "uptime_seconds": int(time.time() - process.create_time()),
            "gmail_helper": GMAIL_HELPER_AVAILABLE,
            "active_threads": threading.active_count(),
            "cleanup_tasks": len(cleanup_progress),
            "env_vars": env_vars
        }
        return jsonify(response_data)
    except Exception as e:
        logger.error(f"Error in health check: {str(e)}")
        return jsonify({"status": "degraded", "error": str(e)})

@app.route('/debug/logs')
def view_logs():
    """View recent logs stored in the circular buffer"""
    level_filter = request.args.get('level', '').upper()
    logs = log_buffer.get_logs() # Get thread-safe copy

    if level_filter and level_filter in ['INFO', 'WARNING', 'ERROR', 'DEBUG', 'CRITICAL']:
        logs = [log for log in logs if log['level'] == level_filter]

    if request.args.get('format') == 'json':
        return jsonify(logs)

    # Simple HTML rendering
    log_html = '''<!DOCTYPE html><html><head><title>EmailWipe Logs</title><style>
        body { font-family: monospace; background: #f4f4f4; color: #333; padding: 15px; font-size: 0.9em;}
        h1 { color: #555; } .log { padding: 5px; margin: 3px 0; border-radius: 3px; border-left: 3px solid; white-space: pre-wrap; word-break: break-word; }
        .ERROR { border-color: #e74c3c; background: #fbeaea; } .WARNING { border-color: #f39c12; background: #fcf3e1; }
        .INFO { border-color: #3498db; background: #eaf3f9; } .DEBUG { border-color: #2ecc71; background: #eafaf1; }
        .CRITICAL { border-color: #9b59b6; background: #f5eef8; }
        .timestamp { color: #7f8c8d; font-size: 0.9em; margin-right: 10px; }
        .controls button, .controls a { background: #3498db; color: white; padding: 6px 12px; border: none; border-radius: 3px; cursor: pointer; margin: 0 5px 10px 0; text-decoration: none; font-size: 0.9em;}
        .controls a.active { background: #2980b9; }
        </style></head><body><h1>EmailWipe Logs</h1>
        <div class="controls">
        <button onclick="location.reload()">Refresh</button>'''
    levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    for level in levels:
        active = ' active' if level_filter == level else ''
        log_html += f'<a href="?level={level}" class="{active}">{level}</a>'
    log_html += '<a href="?" class="' + ('' if level_filter else ' active') + '">ALL</a></div>'
    log_html += f'<p>Showing {len(logs)} log entries</p>'
    for log in reversed(logs): # Show newest first
        log_html += f'<div class="log {log["level"]}"><span class="timestamp">{log["timestamp"]}</span>[{log["level"]}] [{log["logger"]}] {log["message"]}</div>'
    log_html += '</body></html>'
    return log_html


# --- Auth0 OAuth Routes ---
@app.route('/user_info')
def get_user_info():
    """Get user info from session, including token validity"""
    if 'user_email' in session and 'access_token' in session and 'expires_at' in session:
        expires_at_ts = session.get('expires_at', 0)
        now_ts = time.time()
        # Check if valid for at least 5 more minutes (300 seconds)
        is_token_valid = expires_at_ts > (now_ts + 300)
        expires_in_secs = max(0, int(expires_at_ts - now_ts))

        return jsonify({
            "status": "success",
            "email": session['user_email'],
            "auth_provider": session.get('auth_provider', 'generic'),
            "is_gmail": session.get('is_gmail', False),
            "imap_server": session.get('imap_server'),
            "token_valid": is_token_valid,
            "token_expires_in_seconds": expires_in_secs,
            "expires_at_iso": datetime.fromtimestamp(expires_at_ts, timezone.utc).isoformat() if expires_at_ts else None
        })
    else:
        missing = [k for k in ['user_email', 'access_token', 'expires_at'] if k not in session]
        return jsonify({
            "status": "error",
            "message": f"No active user session or token invalid/expired. Missing: {', '.join(missing)}. Please log in.",
            "requires_login": True
        })

@app.route('/auth/login')
def login():
    """Redirect to Auth0 login page"""
    # Generate CSRF protection values
    session['nonce'] = secrets.token_urlsafe(16)
    session['state'] = secrets.token_urlsafe(16)
    redirect_uri = AUTH0_CALLBACK_URL
    logger.debug(f"Login session - nonce: {session['nonce']}, state: {session['state']}")
    
    # Debug session persistence
    logger.debug(f"Session ID exists: {'session_id' in session}")
    logger.debug(f"Full session at login: {dict(session)}")
    auth_params = {
        'redirect_uri': redirect_uri,
        'nonce': session['nonce'],
        'state': session['state'],
    }
    logger.debug(f"Auth params being sent to Auth0: {auth_params}")
    logger.debug(f"Session state before redirect: {session['state']}")
    logger.info(f"Initiating Auth0 login. Nonce: {session['nonce'][:6]}... State: {session['state'][:6]}...")

    # Parameters for Auth0 authorize endpoint
    auth_params = {
        'redirect_uri': redirect_uri,
        'nonce': session['nonce'],
        'state': session['state'],
    }
    logger.debug(f"Auth callback configured with state: {session['state']}")
    logger.debug(f"Full session at login endpoint: {dict(session)}")

    try:
        # Log the constructed authorize URL before redirecting
        authorize_url = auth0.create_authorization_url(**auth_params)['url']
        logger.debug(f"Redirecting to Auth0 authorize URL: {authorize_url}")
        return redirect(authorize_url)
    except Exception as e:
        logger.error(f"Auth0 redirect error: {str(e)}", exc_info=True)
        return render_template('error.html', error="Authentication service error. Please try again later.")


@app.route('/auth/callback')
def callback():
    """Handle Auth0 callback after login including CSRF protection"""
    try:
        # Debug session state before validation
        logger.debug(f"Callback session - Keys: {list(session.keys())}")
        logger.debug(f"Session config: {app.config.get('SESSION_COOKIE_DOMAIN')}")
        
        # Validate CSRF protection params
        state = request.args.get('state')
        session_state = session.get('state')
        
        if not state or not session_state or 'nonce' not in session:
            logger.error(f"Missing auth params. Has state: {bool(state)}, session state: {bool(session_state)}, session nonce: {'nonce' in session}")
            logger.error(f"Request URL: {request.url}")
            logger.error(f"Session ID: {session.sid if 'sid' in session else 'None'}")
            logger.error(f"Session contents: {dict(session)}")
            return render_template('error.html',
                error="Session expired or invalid. Please try again.",
                auth_error=True)

        # Verify state matches exactly
        if state != session['state']:
            logger.error(f"State mismatch! Session: {session['state'][:6]}..., Received: {state[:6]}...")
            return render_template('error.html', error="Security validation failed. Please try again.")
            
        logger.info(f"Auth0 callback validated. State: {state[:6]}..., Code: {'present' if request.args.get('code') else 'missing'}")

        # Check for errors from Auth0
        if 'error' in request.args:
            error = request.args.get('error')
            error_description = request.args.get('error_description', 'Unknown error')
            logger.error(f"Auth0 callback error: {error} - {error_description}")
            return render_template('error.html', error=f"Authentication error: {error_description}")

        # Fetch and validate the token
        logger.info("Auth0 callback processing, fetching token...")
        try:
            auth0_params = {'nonce': session['nonce']}  # Pass stored nonce for validation
            token = auth0.authorize_access_token(**auth0_params)
            if not token or 'access_token' not in token:
                 raise ValueError("Received empty or invalid token response from Auth0.")
            logger.info(f"Token validated. Keys: {list(token.keys())}") # Log keys, not values
            # Verify nonce claim matches session nonce
            if 'userinfo' in token and token['userinfo'].get('nonce') != session['nonce']:
                raise ValueError("Nonce mismatch in token validation")
            # If debugging needed, uncomment below carefully
            # logger.debug(f"Received token data (excluding sensitive parts): {{'expires_in': {token.get('expires_in')}, 'token_type': {token.get('token_type')}}}")

        except Exception as token_error:
            logger.error(f"Error getting access token: {str(token_error)}", exc_info=True)
            err_msg = f"Token error: {str(token_error)}"
            if "invalid_grant" in str(token_error).lower():
                 err_msg = "Authentication session expired or invalid. Please try logging in again."
            elif "invalid_client" in str(token_error).lower():
                 err_msg = "Authentication configuration error (invalid client). Please contact support."
            return render_template('error.html', error=err_msg)

        # Store token details in session
        session['jwt_token'] = token # Store the whole token dict for potential use (e.g., id_token)
        session['access_token'] = token.get('access_token')

        # Calculate and store expiration timestamp (UTC)
        expires_at_timestamp = 0
        if 'expires_in' in token:
            expires_at_timestamp = time.time() + int(token['expires_in'])
            session['expires_at'] = expires_at_timestamp
            logger.info(f"Token expires in {token['expires_in']}s at timestamp {expires_at_timestamp}")
        else:
            logger.warning("Token expiration time ('expires_in') not found in Auth0 response! Setting default 1hr.")
            expires_at_timestamp = time.time() + 3600 # Default to 1 hour
            session['expires_at'] = expires_at_timestamp

        # Get user info (prefer userinfo claim in token if available, else call endpoint)
        userinfo = token.get('userinfo')
        if not userinfo:
             logger.info("Userinfo not in token, calling userinfo endpoint...")
             try:
                  resp = auth0.get('userinfo')
                  resp.raise_for_status() # Check for HTTP errors
                  userinfo = resp.json()
                  logger.info(f"User info fetched via endpoint: {userinfo.get('email', 'unknown')}")
             except Exception as userinfo_error:
                  logger.error(f"Error getting user info from endpoint: {str(userinfo_error)}", exc_info=True)
                  # Critical failure if we can't get email
                  return render_template('error.html', error="Could not retrieve user information. Please try again.")

        session['user_info'] = userinfo
        session['user_email'] = userinfo.get('email')

        if not session['user_email']:
            logger.error("User email could not be determined from token or userinfo endpoint.")
            return render_template('error.html', error="Unable to retrieve user email. Authentication failed.")

        # Determine provider type and IMAP server
        email = session['user_email']
        domain = email.split('@')[-1].lower()
        is_gmail = domain in ['gmail.com', 'googlemail.com']
        session['is_gmail'] = is_gmail
        session['auth_provider'] = 'google' if is_gmail else 'other' # Simplified

        imap_server_found = False
        for domain_suffix, server in DEFAULT_IMAP_SERVERS.items():
            if domain.endswith(domain_suffix):
                session['imap_server'] = server
                imap_server_found = True
                logger.info(f"Identified potential IMAP server: {server} for domain {domain}")
                break
        if not imap_server_found:
            session['imap_server'] = None
            logger.warning(f"No default IMAP server found for domain: {domain}")

        logger.info(f"Authentication successful for {email}. Is Gmail: {is_gmail}. Token expires: {datetime.fromtimestamp(expires_at_timestamp, timezone.utc).isoformat()}")
        # Redirect to main page with success flag
        return redirect(f'/?oauth=success&provider={session["auth_provider"]}')

    except Exception as e:
        logger.critical(f"CRITICAL ERROR during Auth0 callback: {str(e)}", exc_info=True)
        return render_template('error.html', error="An unexpected error occurred during authentication. Please try again or contact support.")

@app.route('/logout')
def logout():
    """Log out user by clearing session and redirecting to Auth0 logout"""
    logger.info(f"Logging out user: {session.get('user_email', 'Unknown')}")
    session.clear() # Clear Flask session

    # Redirect to Auth0 logout endpoint
    # Construct returnTo URL dynamically if possible, else use configured callback base
    base_url = request.host_url # e.g., http://localhost:5050/ or https://yourdomain.com/
    if AUTH0_CALLBACK_URL and '/auth/callback' in AUTH0_CALLBACK_URL:
         base_url = AUTH0_CALLBACK_URL.split('/auth/callback')[0] + '/'

    params = {'returnTo': base_url, 'client_id': AUTH0_CLIENT_ID}
    logout_url = f"{auth0.api_base_url}/v2/logout?{urllib.parse.urlencode(params)}"
    logger.info(f"Redirecting to Auth0 logout URL: {logout_url}")
    return redirect(logout_url)


# --- Core App Functionality Routes ---

@app.route('/verify', methods=['POST'])
def verify():
    """Verify connection, prioritizing API for Gmail, fallback to IMAP."""
    start_time = time.time()
    data = request.json
    auth_method = data.get('auth_method', 'password')
    logger.info(f"Received verification request with method: {auth_method}")

    access_token = email = expires_at = password = imap_server = None
    is_gmail = False

    # --- Get Credentials ---
    if auth_method == 'oauth':
        if 'access_token' not in session or 'user_email' not in session or 'expires_at' not in session:
            logger.warning("OAuth verification attempt failed: Missing session data.")
            return jsonify({"status": "error", "message": "OAuth session invalid or expired. Please log in again.", "requires_login": True}), 401
        access_token = session['access_token']
        email = session['user_email']
        expires_at = session['expires_at']
        is_gmail = session.get('is_gmail', False)
        imap_server = session.get('imap_server') # Potential IMAP server from session
        logger.info(f"Verifying OAuth connection for {email}. Is Gmail: {is_gmail}. Token expires at: {expires_at}")
        # Extra check for token expiration before proceeding
        if expires_at < time.time() + 60: # Check if expires within 1 min
             logger.warning("OAuth token is expired or about to expire.")
             return jsonify({"status": "error", "message": "Your session token has expired. Please log in again.", "requires_login": True}), 401
        if not expires_at: # Handle missing expires_at value
            logger.error("Missing 'expires_at' value in session. Please try logging in again.")
            return jsonify({"status": "error", "message": "Session data is incomplete. Please log in again.", "requires_login": True}), 401

    else: # Password auth
        email = data.get('username')
        password = data.get('password')
        imap_server = data.get('imap_server')
        if not all([email, password, imap_server]):
             logger.warning("Password verification attempt failed: Missing credentials or server.")
             return jsonify({"status": "error", "message": "Username, password, and IMAP server required."}), 400
        is_gmail = 'gmail.com' in imap_server.lower() or 'googlemail.com' in imap_server.lower()
        logger.info(f"Verifying password connection for {email} on {imap_server}")

    # --- Perform Verification ---
    connection_ok = False
    message = "Verification failed."
    verification_method = "failed"
    requires_reauth = False

    try:
        if auth_method == 'oauth' and is_gmail and GMAIL_HELPER_AVAILABLE:
            logger.info("Attempting verification via Gmail API helper...")
            connection_ok, message, verification_method = gmail_api_helper.verify_connection(email, access_token, expires_at)
            if not connection_ok and verification_method == "failed":
                logger.error(f"Gmail verification failed via helper: {message}")
                requires_reauth = "reauthentication" in message or "Authentication" in message or "Permission" in message
                # Return immediately if helper confirmed failure for both methods
                return jsonify({
                    "status": "error", "message": f"Gmail Connection Failed: {message}",
                    "time_taken": f"{time.time() - start_time:.2f}s", "is_gmail": True, "requires_reauth": requires_reauth
                }), 400 # Or 401 if reauth needed
            elif connection_ok:
                 logger.info(f"Verification successful via helper ({verification_method}).")
            # If helper succeeded via IMAP (api failed), proceed to return success below

        # --- IMAP verification (Password auth OR OAuth fallback if API unavailable/failed but IMAP might work) ---
        elif imap_server:
             # Avoid re-running IMAP if helper already succeeded via IMAP
             if not (connection_ok and verification_method == "imap"):
                logger.info(f"Attempting verification via IMAP ({auth_method}) for {email} on {imap_server}")
                imap_conn = None
                imap_error = None
                try:
                    current_timeout = socket.getdefaulttimeout()
                    socket.setdefaulttimeout(CONNECTION_TIMEOUT) # Set timeout for operation
                    if auth_method == 'oauth':
                        imap_conn, imap_error = gmail_api_helper.connect_imap_oauth(email, access_token)
                    else: # Password auth
                        context = ssl.create_default_context()
                        context.check_hostname = False; context.verify_mode = ssl.CERT_NONE # Use with caution
                        imap_conn = imaplib.IMAP4_SSL(imap_server, DEFAULT_IMAP_PORT, ssl_context=context, timeout=CONNECTION_TIMEOUT)
                        imap_conn.login(email, password)
                        logger.info("IMAP password login successful.")

                    if imap_conn:
                        status, _ = imap_conn.select("INBOX", readonly=True) # Basic check
                        if status == 'OK':
                            connection_ok = True
                            message = f"IMAP connection verified successfully ({auth_method})."
                            verification_method = "imap"
                            logger.info(message)
                        else:
                             imap_error = "Failed to select INBOX after login."
                             logger.warning(imap_error)
                        imap_conn.logout()
                    elif imap_error:
                         # Error came from connect_imap_oauth helper
                         message = f"IMAP Connection Failed: {imap_error}"
                         logger.error(message)
                         requires_reauth = "Invalid Credentials" in imap_error or "Authentication Error" in imap_error
                    else:
                         # Should not happen if auth succeeded, but handle defensively
                         imap_error = "IMAP connection failed unexpectedly after authentication."
                         logger.error(imap_error)

                except imaplib.IMAP4.error as e:
                    imap_error = f"IMAP Error: {str(e)}"
                    message = f"Authentication or IMAP command failed: {str(e)}"
                    logger.error(f"{imap_error} for {email}")
                    requires_reauth = "authenticate" in str(e).lower() or "credentials" in str(e).lower()
                except socket.timeout:
                    imap_error = "IMAP connection timed out."
                    message = f"Connection to {imap_server} timed out ({CONNECTION_TIMEOUT}s)."
                    logger.error(message)
                except Exception as e:
                    imap_error = f"Unexpected IMAP error: {str(e)}"
                    message = f"An unexpected error occurred: {str(e)}"
                    logger.error(f"{imap_error} for {email}", exc_info=True)

                # If IMAP failed, return error (unless API already succeeded)
                if not connection_ok:
                     if verification_method == "api": # API worked before, IMAP fallback failed
                          message = f"Gmail API verified, but IMAP check failed: {imap_error}. Proceeding based on API success."
                          logger.warning(message)
                          connection_ok = True # Restore API success state
                     else: # Both API (if tried) and IMAP failed
                          return jsonify({
                              "status": "error", "message": message,
                              "time_taken": f"{time.time() - start_time:.2f}s", "is_gmail": is_gmail, "requires_reauth": requires_reauth
                          }), 400 # Or 401 if reauth needed
        else:
             # No IMAP server specified and not a successful Gmail API verification
             message = "Cannot verify: No IMAP server provided and Gmail API check was not successful or applicable."
             logger.warning(message)
             return jsonify({"status": "error", "message": message, "is_gmail": is_gmail}), 400

    except Exception as e:
         logger.error(f"Unexpected error during verification route: {str(e)}", exc_info=True)
         return jsonify({"status": "error", "message": f"An internal error occurred: {str(e)}"}), 500

    # --- Return Success Response ---
    if connection_ok:
        total_time = time.time() - start_time
        return jsonify({
            "status": "success", "message": message,
            "time_taken": f"{total_time:.2f}s", "verification_method": verification_method, "is_gmail": is_gmail
        })
    else:
         # Should technically be caught earlier, but as a final fallback
         logger.error(f"Verification ended without success status. Last message: {message}")
         return jsonify({
              "status": "error", "message": message or "Verification failed for an unknown reason.",
              "time_taken": f"{time.time() - start_time:.2f}s", "is_gmail": is_gmail, "requires_reauth": requires_reauth
         }), 400


@app.route('/get_folders', methods=['POST'])
def get_folders():
    start_time = time.time()
    data = request.json
    auth_method = data.get('auth_method', 'password')
    logger.info(f"Received get_folders request with method: {auth_method}")

    access_token = email = expires_at = password = imap_server = None
    is_gmail = False

    # --- Get Credentials ---
    if auth_method == 'oauth':
        if 'access_token' not in session or 'user_email' not in session or 'expires_at' not in session:
            logger.warning("Get Folders failed: Missing session data.")
            return jsonify({"status": "error", "message": "OAuth session invalid or expired. Please log in again.", "requires_login": True}), 401
        access_token = session['access_token']
        email = session['user_email']
        expires_at = session['expires_at']
        is_gmail = session.get('is_gmail', False)
        imap_server = session.get('imap_server')
        logger.info(f"Getting folders via OAuth for {email}. Is Gmail: {is_gmail}")
        if expires_at < time.time() + 60:
             logger.warning("OAuth token is expired or about to expire during get_folders.")
             return jsonify({"status": "error", "message": "Your session token has expired. Please log in again.", "requires_login": True}), 401
    else: # Password auth
        email = data.get('username')
        password = data.get('password')
        imap_server = data.get('imap_server')
        if not all([email, password, imap_server]):
            logger.warning("Get Folders password attempt failed: Missing credentials or server.")
            return jsonify({"status": "error", "message": "Username, password, and IMAP server required."}), 400
        is_gmail = 'gmail.com' in imap_server.lower() or 'googlemail.com' in imap_server.lower()
        logger.info(f"Getting folders via password for {email} on {imap_server}")

    folders = []
    total_messages = 0
    total_size = 0 # Size is hard/slow to get accurately, especially via API labels
    method_used = "unknown"
    error_message = None

    # --- Try Gmail API First ---
    if auth_method == 'oauth' and is_gmail and GMAIL_HELPER_AVAILABLE:
        logger.info("Attempting to get folders via Gmail API helper...")
        service, service_error = gmail_api_helper.create_gmail_service(access_token, expires_at)
        if service:
            folders_result, labels_error = gmail_api_helper.get_gmail_labels_as_folders(service)
            if folders_result is not None:
                folders = folders_result
                total_messages = sum(f.get('messageCount', 0) for f in folders)
                total_size = sum(f.get('size', 0) for f in folders) # Will be 0 from helper currently
                method_used = "gmail_api"
                logger.info(f"Successfully retrieved {len(folders)} labels/folders via Gmail API.")
            else:
                error_message = f"Gmail API Error getting labels: {labels_error}"
                logger.warning(error_message + ". Falling back to IMAP if possible.")
        else:
            error_message = f"Gmail API Error creating service: {service_error}"
            logger.warning(error_message + ". Falling back to IMAP if possible.")
            if "reauthentication" in error_message or "Authentication" in error_message:
                 return jsonify({"status": "error", "message": error_message, "requires_login": True}), 401

    # --- Fallback to IMAP or Primary IMAP ---
    # Only run if API didn't succeed OR if it's not a Gmail OAuth request
    if not folders and imap_server:
        logger.info(f"Attempting to get folders via IMAP ({auth_method}) from {imap_server}")
        method_used = "imap"
        imap_conn = None
        try:
            socket.setdefaulttimeout(CONNECTION_TIMEOUT)
            if auth_method == 'oauth':
                imap_conn, imap_error = gmail_api_helper.connect_imap_oauth(email, access_token)
                if imap_error: raise imaplib.IMAP4.error(imap_error)
            else:
                context = ssl.create_default_context(); context.check_hostname=False; context.verify_mode=ssl.CERT_NONE
                imap_conn = imaplib.IMAP4_SSL(imap_server, DEFAULT_IMAP_PORT, ssl_context=context, timeout=CONNECTION_TIMEOUT)
                imap_conn.login(email, password)

            if not imap_conn: raise imaplib.IMAP4.error("IMAP connection failed.")

            status, folder_list_raw = imap_conn.list()
            if status != 'OK': raise imaplib.IMAP4.error(f"Failed to list IMAP folders: {folder_list_raw}")

            logger.info(f"Parsing {len(folder_list_raw)} raw IMAP folder entries...")
            # --- Use your preferred IMAP Folder Parsing Logic Here ---
            # (Keeping the simplified version from previous step as placeholder)
            for folder_info_raw in folder_list_raw:
                 if not folder_info_raw: continue
                 try:
                      decoded_info = folder_info_raw.decode('utf-8', errors='ignore')
                      parts = decoded_info.split('"')
                      folder_name = None
                      if len(parts) > 1:
                           for i in range(len(parts) - 1, 0, -1):
                                if parts[i].strip() and parts[i] != '/':
                                     folder_name = parts[i]; break
                      if not folder_name:
                            space_parts = decoded_info.split()
                            if space_parts: folder_name = space_parts[-1].strip('"')

                      if not folder_name or not folder_name.strip(): continue

                      original_folder_name = folder_name
                      display_name = folder_name.split('/')[-1] if '/' in folder_name else folder_name
                      display_name = display_name.replace('&', '&').replace('<', '<').replace('>', '>')

                      # Get count/size estimate (can be slow)
                      message_count = 0; size = 0
                      try:
                           # Select folder (try quoted first)
                           select_status, select_info = 'NO', [b'0']
                           try: select_status, select_info = imap_conn.select(f'"{original_folder_name}"', readonly=True)
                           except:
                                try: select_status, select_info = imap_conn.select(original_folder_name, readonly=True)
                                except Exception as select_e: logger.debug(f"Non-critical: Failed select for '{original_folder_name}': {select_e}")

                           if select_status == 'OK':
                                message_count = int(select_info[0])
                                # Simple size estimate: Count * 15KB average
                                size = message_count * 15000
                      except Exception as e: logger.warning(f"Error getting stats for folder {original_folder_name}: {e}")

                      folders.append({
                          'name': original_folder_name, 'displayName': display_name,
                          'messageCount': message_count, 'size': size, 'sizeFormatted': format_size(size)
                      })
                      total_messages += message_count; total_size += size
                 except Exception as parse_e: logger.warning(f"Error parsing IMAP folder entry: {parse_e}")
            # --- End IMAP Parsing ---

            # Sort folders
            common_folders = ['INBOX', 'Sent', 'Drafts', 'Trash', 'Spam', 'Archive', 'Junk'] # Add common names
            def folder_sort_key(f):
                 dn = f.get('displayName', f.get('name', ''))
                 try: return common_folders.index(dn)
                 except ValueError: return len(common_folders) + 1
            folders.sort(key=lambda f: (folder_sort_key(f), -f.get('messageCount', 0)))

            imap_conn.logout()
            logger.info(f"Successfully retrieved {len(folders)} folders via IMAP.")

        except Exception as e:
            # Log error but don't necessarily fail if API worked previously
            imap_err_msg = f"IMAP Error getting folders: {str(e)}"
            logger.error(imap_err_msg, exc_info=True)
            if imap_conn: 
                try: 
                    imap_conn.logout() 
                except: 
                    pass
            # If API also failed, this becomes the primary error
            if method_used != "gmail_api":
                 error_message = imap_err_msg # Set IMAP error as the main one
                 # Check if it's an auth error requiring re-login
                 if "authenticate" in str(e).lower() or "credentials" in str(e).lower():
                      return jsonify({"status": "error", "message": error_message, "requires_login": True}), 401

    # --- Return results ---
    if folders:
        total_time = time.time() - start_time
        return jsonify({
            "status": "success", "folders": folders, "totalMessages": total_messages,
            "totalSize": total_size, "totalSizeFormatted": format_size(total_size) if total_size > 0 else ("N/A" if method_used == "gmail_api" else "0 B"),
            "time_taken": f"{total_time:.2f}s", "method": method_used
        })
    else:
        # Both API and IMAP failed or were skipped
        final_error = error_message or "Could not retrieve folders."
        if not imap_server and not is_gmail: final_error = "IMAP server not configured for this account."
        logger.error(f"Final result for get_folders: Failed. Error: {final_error}")
        return jsonify({"status": "error", "message": final_error}), 500 # Or 400


@app.route('/progress/<task_id>', methods=['GET'])
def get_progress(task_id):
    """Get progress for a specific cleanup task"""
    with progress_lock:
        task_progress = cleanup_progress.get(task_id)
        task_status = cleanup_running_status.get(task_id)

    if not task_progress:
        return jsonify({"status": "error", "message": "Task not found or expired."}), 404

    # Check for potential stalls (e.g., stuck during estimation)
    if task_status and not task_progress.get('completed', False) and not task_progress.get('error'):
        last_update = task_status.get('last_update', 0)
        current_phase = task_status.get('phase', 'unknown')
        now = time.time()
        # If no update for > 60 seconds, indicate potential issue
        if now - last_update > 60:
             task_progress['status_message'] = f"Processing seems slow (Phase: {current_phase}, No update for {int(now - last_update)}s)"
             logger.warning(f"[Task {task_id}] Potential stall detected. Last update {int(now - last_update)}s ago in phase {current_phase}.")
        else:
             task_progress.pop('status_message', None) # Clear message if progressing


    return jsonify({
        "status": "success",
        "progress": task_progress
    })


@app.route('/clean', methods=['POST'])
def clean_emails():
    """Start email cleanup process, prioritizing API for Gmail."""
    start_time = time.time()
    data = request.json
    folders_to_clean = data.get('folders', []) # Expecting list of folder names/IDs
    cutoff_date_str = data.get('cutoff_date', DEFAULT_CUTOFF_DATE)
    auth_method = data.get('auth_method', 'password')

    logger.info(f"Received cleanup request. Method: {auth_method}. Folders: {folders_to_clean}. Cutoff: {cutoff_date_str}")

    if not folders_to_clean:
         return jsonify({"status": "error", "message": "No folders selected for cleaning."}), 400

    # --- Validate Date ---
    try:
        dt_cutoff = datetime.strptime(cutoff_date_str, '%d-%b-%Y')
        # Ensure it's sufficiently in the past (e.g., at least 7 days ago) to prevent accidental recent deletion
        if dt_cutoff > datetime.now() - timedelta(days=7):
             return jsonify({"status": "error", "message": "Cutoff date must be at least 7 days in the past."}), 400
        gmail_api_date_format = dt_cutoff.strftime('%Y/%m/%d')
        imap_date_format = dt_cutoff.strftime('%d-%b-%Y')
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid cutoff date format. Use DD-Mon-YYYY (e.g., 01-Jan-2021)."}), 400

    # --- Get Credentials ---
    access_token = email = expires_at = password = imap_server = None
    is_gmail = False
    if auth_method == 'oauth':
        if 'access_token' not in session or 'user_email' not in session or 'expires_at' not in session:
            return jsonify({"status": "error", "message": "OAuth session invalid or expired. Please log in again.", "requires_login": True}), 401
        access_token = session['access_token']; email = session['user_email']; expires_at = session['expires_at']
        is_gmail = session.get('is_gmail', False); imap_server = session.get('imap_server')
        if expires_at < time.time() + 60:
             return jsonify({"status": "error", "message": "Your session token has expired. Please log in again.", "requires_login": True}), 401
    else:
        email = data.get('username'); password = data.get('password'); imap_server = data.get('imap_server')
        if not all([email, password, imap_server]):
             return jsonify({"status": "error", "message": "Username, password, and IMAP server required."}), 400
        is_gmail = 'gmail.com' in imap_server.lower() or 'googlemail.com' in imap_server.lower()

    # --- Generate Task ID and Initialize Progress ---
    task_id = str(uuid.uuid4())
    current_time = time.time()
    with progress_lock:
        cleanup_progress[task_id] = {
            "overall_progress": 0, "current_folder": "Initializing...", "current_folder_progress": 0,
            "folders_completed": 0, "total_folders": len(folders_to_clean),
            "total_emails_deleted": 0, "total_size_deleted": 0, "results": {},
            "completed": False, "start_time": current_time, "error": None,
            "cutoff_date": cutoff_date_str, "method_used": "pending"
        }
        cleanup_running_status[task_id] = {"last_update": current_time, "phase": "initializing"}

    # --- Start Background Thread ---
    logger.info(f"Starting background cleanup task {task_id} for {email}")
    thread = threading.Thread(target=process_cleanup, name=f"Cleaner-{task_id[:6]}", args=(
        task_id, email, password, imap_server, folders_to_clean,
        gmail_api_date_format, imap_date_format,
        auth_method, access_token, expires_at, is_gmail
    ))
    thread.daemon = True # Allow app to exit even if thread is running
    thread.start()

    # Return task_id for polling
    return jsonify({
        "status": "success",
        "message": f"Cleanup task started ({len(folders_to_clean)} folders). Track progress using task ID.",
        "task_id": task_id
    })


def process_cleanup(task_id, email, password, imap_server, folders_to_clean,
                    gmail_api_date_format, imap_date_format,
                    auth_method, access_token, expires_at, is_gmail):
    """Background task to process email cleanup."""
    start_time = time.time()
    # Get references to the shared progress dicts (use lock when updating)
    # No need to pass prog/prog_status down if we update directly using task_id and lock

    def update_progress(updates):
        """Safely update progress dictionaries."""
        with progress_lock:
            if task_id in cleanup_progress:
                 cleanup_progress[task_id].update(updates)
                 # Always update timestamp on status change
                 if task_id in cleanup_running_status:
                      cleanup_running_status[task_id]['last_update'] = time.time()
                      if 'phase' in updates:
                           cleanup_running_status[task_id]['phase'] = updates['phase']
                 else: # Should not happen but initialize if missing
                      cleanup_running_status[task_id] = {"last_update": time.time(), "phase": updates.get('phase', 'unknown')}


    logger.info(f"[Task {task_id}] Background process started. Method: {auth_method}, Gmail: {is_gmail}")

    use_api = auth_method == 'oauth' and is_gmail and GMAIL_HELPER_AVAILABLE
    service = None
    imap_conn = None
    method_used_final = "unknown"

    try:
        update_progress({"current_folder": "Connecting...", "phase": "connecting", "overall_progress": 5})
        method_used_final = "api" if use_api else "imap"
        update_progress({"method_used": method_used_final}) # Record method being attempted

        # --- Connect / Create Service ---
        if use_api:
            logger.info(f"[Task {task_id}] Creating Gmail service...")
            service, service_error = gmail_api_helper.create_gmail_service(access_token, expires_at)
            if not service:
                 logger.warning(f"[Task {task_id}] Gmail service creation failed: {service_error}. Falling back to IMAP.")
                 update_progress({"results": {"API_Error_Connect": f"Service creation failed: {service_error}"}})
                 use_api = False; method_used_final = "imap"
                 update_progress({"method_used": method_used_final})
                 if not imap_server: raise ConnectionError(f"API failed and no IMAP server: {service_error}")
            else:
                 logger.info(f"[Task {task_id}] Gmail service created. Verifying...")
                 api_ok, api_msg = gmail_api_helper.verify_gmail_api_connection(service)
                 if not api_ok:
                      logger.warning(f"[Task {task_id}] Gmail service verification failed: {api_msg}. Falling back to IMAP.")
                      update_progress({"results": {"API_Error_Verify": f"Service verification failed: {api_msg}"}})
                      use_api = False; method_used_final = "imap"
                      update_progress({"method_used": method_used_final})
                      if not imap_server: raise ConnectionError(f"API verification failed and no IMAP server: {api_msg}")
                 else:
                      logger.info(f"[Task {task_id}] Gmail service verified.")


        if not use_api:
            if not imap_server: raise ValueError("IMAP server address required for non-API cleanup.")
            logger.info(f"[Task {task_id}] Connecting via IMAP ({auth_method}) to {imap_server}...")
            # Longer timeout for potentially long-running cleanup operations
            current_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(CONNECTION_TIMEOUT * 3) # e.g., 90 seconds

            try:
                if auth_method == 'oauth':
                    imap_conn, imap_error = gmail_api_helper.connect_imap_oauth(email, access_token)
                else:
                    context = ssl.create_default_context(); context.check_hostname=False; context.verify_mode=ssl.CERT_NONE
                    imap_conn = imaplib.IMAP4_SSL(imap_server, DEFAULT_IMAP_PORT, ssl_context=context)
                    imap_conn.login(email, password)
                    imap_error = None
                if not imap_conn: raise ConnectionError(f"Failed to connect via IMAP: {imap_error or 'Unknown reason'}")
                logger.info(f"[Task {task_id}] IMAP connection successful.")
            finally:
                 socket.setdefaulttimeout(current_timeout) # Restore default timeout


        # --- Process Folders ---
        update_progress({"overall_progress": 10, "phase": "processing_folders", "current_folder": f"Starting {len(folders_to_clean)} folders..."})
        total_emails_deleted_overall = 0
        total_size_deleted_overall = 0

        for i, folder_name in enumerate(folders_to_clean):
             # Check if task was cancelled (e.g., via another mechanism - not implemented here)
             # if task_is_cancelled(task_id): break

             folder_start_time = time.time()
             logger.info(f"[Task {task_id}] Processing folder {i+1}/{len(folders_to_clean)}: '{folder_name}' using {'API' if use_api else 'IMAP'}")
             update_progress({
                 "current_folder": folder_name,
                 "current_folder_progress": 0,
                 "phase": f"processing_{folder_name}"
             })

             deleted_count = 0; deleted_size = 0; folder_error = None; folder_status = "success"

             try:
                 if use_api:
                     # API: Assume folder_name is label ID (needs robust mapping in real app)
                     label_id = folder_name
                     query = f"label:{label_id} before:{gmail_api_date_format}"
                     logger.info(f"[Task {task_id}] Using API query: {query}")
                     # Create a temporary dict for the helper to update folder progress/totals
                     folder_progress_data = {"total_emails_deleted": 0, "total_size_deleted": 0, "current_folder_progress": 0}
                     deleted_count, deleted_size, folder_error = gmail_api_helper.delete_emails_gmail_api(
                         service, query, task_id, folder_progress_data # Pass temp dict
                     )
                     if folder_error: raise Exception(f"API Deletion Error: {folder_error}")
                     # Update overall totals from the temporary dict results
                     total_emails_deleted_overall += folder_progress_data["total_emails_deleted"]
                     total_size_deleted_overall += folder_progress_data["total_size_deleted"]
                     # Update main progress dict with totals accumulated so far
                     update_progress({
                          "total_emails_deleted": total_emails_deleted_overall,
                          "total_size_deleted": total_size_deleted_overall
                     })

                 else: # IMAP
                     logger.info(f"[Task {task_id}] Selecting IMAP folder: '{folder_name}'")
                     socket.setdefaulttimeout(CONNECTION_TIMEOUT * 2) # Timeout for select/search
                     try:
                          # Use robust selection (quotes first)
                          select_status = 'NO'
                          try: select_status, _ = imap_conn.select(f'"{folder_name}"')
                          except: select_status, _ = imap_conn.select(folder_name)
                          if select_status != 'OK': raise Exception("Could not select IMAP folder.")

                          search_command = f'(BEFORE "{imap_date_format}")'
                          logger.info(f"[Task {task_id}] Searching IMAP with: {search_command}")
                          status, messages = imap_conn.search(None, search_command)
                          if status != 'OK': raise Exception(f"IMAP search failed: {messages}")
                     finally:
                          socket.setdefaulttimeout(current_timeout) # Restore default

                     message_ids = messages[0].split()
                     total_to_delete = len(message_ids)
                     logger.info(f"[Task {task_id}] Found {total_to_delete} emails via IMAP search.")

                     if total_to_delete > 0:
                          # Estimate size roughly (replace with sampling if needed)
                          folder_size_estimate = total_to_delete * 15000

                          # Process in batches
                          for batch_start in range(0, total_to_delete, BATCH_SIZE):
                               batch_ids = message_ids[batch_start:min(batch_start + BATCH_SIZE, total_to_delete)]
                               batch_id_str = ','.join(id.decode() for id in batch_ids)
                               batch_s = len(batch_ids)

                               logger.info(f"[Task {task_id}] Marking batch {batch_start//BATCH_SIZE + 1} ({batch_s} emails) as deleted...")
                               socket.setdefaulttimeout(CONNECTION_TIMEOUT) # Standard timeout for store/expunge
                               try:
                                    store_status, _ = imap_conn.store(batch_id_str, '+FLAGS', '\\Deleted')
                                    if store_status != 'OK':
                                         logger.warning(f"[Task {task_id}] IMAP store command failed for batch. Skipping.")
                                         continue
                               finally:
                                    socket.setdefaulttimeout(current_timeout)

                               deleted_count += batch_s
                               folder_progress = min(100, (deleted_count / total_to_delete) * 100)
                               # Update overall progress estimate
                               overall_prog = min(95, 10 + ((i + (deleted_count/total_to_delete)) / len(folders_to_clean)) * 85)
                               # Accumulate totals directly
                               total_emails_deleted_overall += batch_s
                               total_size_deleted_overall += (batch_s / total_to_delete) * folder_size_estimate if total_to_delete else 0

                               update_progress({
                                   "total_emails_deleted": total_emails_deleted_overall,
                                   "total_size_deleted": total_size_deleted_overall,
                                   "current_folder_progress": folder_progress,
                                   "overall_progress": overall_prog
                               })
                               time.sleep(0.05) # Tiny sleep between batches

                          # Expunge after all batches for the folder
                          if deleted_count > 0:
                               logger.info(f"[Task {task_id}] Expunging {deleted_count} emails from '{folder_name}'...")
                               socket.setdefaulttimeout(CONNECTION_TIMEOUT * 2) # Longer timeout for expunge
                               try:
                                    expunge_status, expunge_data = imap_conn.expunge()
                                    if expunge_status != 'OK': logger.warning(f"[Task {task_id}] Expunge failed for folder '{folder_name}': {expunge_data}")
                                    else: logger.info(f"[Task {task_id}] Expunge successful.")
                               finally:
                                    socket.setdefaulttimeout(current_timeout)
                          deleted_size = folder_size_estimate # Use estimate for reporting

             except Exception as e:
                 folder_error = str(e)
                 folder_status = "error"
                 logger.error(f"[Task {task_id}] Error processing folder '{folder_name}': {folder_error}", exc_info=True)

             # Record final result for the folder
             with progress_lock:
                 # Ensure results dict exists
                 if task_id in cleanup_progress and 'results' not in cleanup_progress[task_id]:
                      cleanup_progress[task_id]['results'] = {}

                 if task_id in cleanup_progress:
                      cleanup_progress[task_id]['results'][folder_name] = {
                          "status": folder_status,
                          "message": f"Deleted {deleted_count} emails." if folder_status == "success" else folder_error,
                          "count": deleted_count,
                          "size": deleted_size
                      }
                      cleanup_progress[task_id]["folders_completed"] += 1
                      # Ensure overall progress reflects completion of this folder step
                      cleanup_progress[task_id]["overall_progress"] = min(95, 10 + (cleanup_progress[task_id]["folders_completed"] / len(folders_to_clean)) * 85)
                 # Update status outside results dict
                 update_progress({"current_folder_progress": 100}) # Mark folder 100% done

             folder_time = time.time() - folder_start_time
             logger.info(f"[Task {task_id}] Finished folder '{folder_name}' in {folder_time:.2f}s. Status: {folder_status}. Deleted: {deleted_count}")

        # --- Final Cleanup ---
        logger.info(f"[Task {task_id}] All folders processed. Logging out.")
        if imap_conn:
            try: imap_conn.logout()
            except Exception as logout_e: logger.warning(f"[Task {task_id}] Error during IMAP logout: {logout_e}")
        # No equivalent needed for API service object

        total_time_taken = time.time() - start_time
        logger.info(f"[Task {task_id}] Cleanup finished in {total_time_taken:.2f} seconds. Total deleted: {total_emails_deleted_overall}")
        final_updates = {
            "overall_progress": 100, "current_folder": "Complete", "completed": True,
            "time_taken": f"{total_time_taken:.2f} seconds", "phase": "completed",
            "total_emails_deleted": total_emails_deleted_overall, # Ensure final accurate totals
            "total_size_deleted": total_size_deleted_overall
        }
        update_progress(final_updates)

    except Exception as e:
        logger.critical(f"[Task {task_id}] FATAL ERROR during cleanup process: {str(e)}", exc_info=True)
        error_updates = {"error": str(e), "completed": True, "current_folder": "Error", "phase": "error", "overall_progress": 100}
        update_progress(error_updates)
        # Attempt logout if connection exists
        if imap_conn:
            try: imap_conn.logout()
            except: pass
    finally:
         # Ensure default socket timeout is restored if process crashes mid-operation
         socket.setdefaulttimeout(CONNECTION_TIMEOUT)
         logger.info(f"[Task {task_id}] Background process finished.")


# --- Helper Functions ---

def format_size(size_bytes):
    """Format size in bytes to human-readable format"""
    if not isinstance(size_bytes, (int, float)) or size_bytes < 0: return "N/A"
    if size_bytes < 1024: return f"{size_bytes} B"
    size_kb = size_bytes / 1024
    if size_kb < 1024: return f"{size_kb:.1f} KB"
    size_mb = size_kb / 1024
    if size_mb < 1024: return f"{size_mb:.1f} MB"
    size_gb = size_mb / 1024
    return f"{size_gb:.1f} GB"

# --- Error Handlers ---
@app.errorhandler(400)
def bad_request(error):
    logger.warning(f"Bad Request (400): {error.description}")
    return jsonify({"status": "error", "message": error.description or "Bad request"}), 400

@app.errorhandler(401)
def unauthorized(error):
    logger.warning(f"Unauthorized (401): {error.description}")
    return jsonify({"status": "error", "message": error.description or "Unauthorized", "requires_login": True}), 401

@app.errorhandler(404)
def not_found(error):
    logger.info(f"Not Found (404): {request.path}")
    return jsonify({"status": "error", "message": "Resource not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors with proper logging"""
    # Log the actual exception if available
    if hasattr(error, 'original_exception'):
        logger.error("Internal Server Error (500)", exc_info=error.original_exception)
    else:
        logger.error(f"Internal Server Error (500): {error}")
    return render_template('500.html', error=str(error)), 500


# --- Main Execution ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5050))
    # Debug mode enabled if not running in a known production env (like Railway)
    is_production = os.environ.get('RAILWAY_ENVIRONMENT') is not None or \
                    os.environ.get('DYNO') is not None # Add other PaaS indicators if needed
    debug_mode = not is_production

    logger.info(f"Starting Flask app. Debug mode: {debug_mode}. Production: {is_production}")
    # Use Gunicorn in production, Flask's development server otherwise
    if is_production:
         logger.warning("Running in production mode - Gunicorn should be used via Procfile/startup command.")
         # The app.run() below is mainly for local development.
         # In production, a WSGI server like Gunicorn runs the 'app' object.
         # Example Gunicorn command: gunicorn --bind 0.0.0.0:$PORT app:app --workers 2 --threads 4 --timeout 120

    try:
        logger.info(f"Flask development server starting on http://0.0.0.0:{port}")
        # host='0.0.0.0' makes it accessible externally (needed for containers/PaaS)
        # Use threaded=True for handling multiple requests during development (like polling progress)
        app.run(host='0.0.0.0', port=port, debug=debug_mode, threaded=True)
    except Exception as e:
        logger.critical(f"Failed to start Flask application: {e}", exc_info=True)
        sys.exit(1) # Exit if server fails to start