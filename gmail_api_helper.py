# gmail_api_helper.py
import imaplib
import logging
import json
from datetime import datetime, timedelta
from typing import Tuple, Optional, Any
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)

# Keep full scope for testing but add expiration safeguards
SCOPES = ['https://mail.google.com/']

class SecureAuth0Credentials(Credentials):
    """Enhanced credential handling with expiration safeguards"""
    def __init__(self, token: str, expires_at: float):
        super().__init__(token=token)
        self.expires_at = datetime.utcfromtimestamp(expires_at)
        self.token = token  # Explicit storage
        logger.info(f"Token initialized, expires: {self.expires_at.isoformat()}")
        
    def refresh(self, request):
        """Block refresh attempts with clear guidance"""
        logger.critical("Auth0 token refresh attempted - initiate reauthentication")
        raise ValueError("Session expired - please reauthenticate")
    
    @property
    def valid(self) -> bool:
        """Check with 5-minute buffer for token expiration"""
        return bool(self.token) and (datetime.utcnow() < self.expires_at - timedelta(minutes=5))

def create_gmail_service(token: str, expires_at: float) -> Tuple[Any, Optional[str]]:
    """Create Gmail service with expiration validation"""
    try:
        creds = SecureAuth0Credentials(token, expires_at)
        if not creds.valid:
            raise ValueError("Token expired or invalid - requires reauthentication")
            
        return build('gmail', 'v1', credentials=creds, cache_discovery=False), None
        
    except Exception as e:
        logger.error(f"Service creation failed: {str(e)}")
        return None, str(e)

def connect_imap_oauth(email: str, token: str) -> Tuple[Optional[imaplib.IMAP4_SSL], Optional[str]]:
    """IMAP fallback with robust XOAUTH2 handling"""
    try:
        imap = imaplib.IMAP4_SSL('imap.gmail.com', 993)
        auth_str = f"user={email}\x01auth=Bearer {token}\x01\x01".encode()
        imap.authenticate('XOAUTH2', lambda x: auth_str)
        return imap, None
    except imaplib.IMAP4.error as e:
        error = f"IMAP Error: {str(e)}. Check token scopes and expiration."
        logger.error(error)
        return None, error
    except Exception as e:
        error = f"IMAP Connection Failed: {str(e)}"
        logger.error(error)
        return None, error

def verify_connection(email: str, token: str, expires_at: float) -> Tuple[bool, str]:
    """Comprehensive connection verification with failover"""
    # First attempt: Gmail API
    service, error = create_gmail_service(token, expires_at)
    if service:
        try:
            service.users().labels().list(userId='me').execute()
            return True, "Gmail API verification successful"
        except HttpError as e:
            logger.error(f"Gmail API Error: {e.resp.status} {e._get_reason()}")
    
    # Fallback: IMAP OAuth
    imap, imap_error = connect_imap_oauth(email, token)
    if imap:
        imap.logout()
        return True, "IMAP verification successful"
        
    # Final failure analysis
    error_msg = "All verification methods failed:\n"
    error_msg += f"- Gmail API: {error}\n" if error else ""
    error_msg += f"- IMAP: {imap_error}" if imap_error else ""
    return False, error_msg

def manual_token_check(token: str) -> dict:
    """Manual token verification for debugging"""
    try:
        # Decode JWT without validation
        decoded = json.loads(base64.b64decode(token.split('.')[1] + "==="))
        return {
            "expires_at": datetime.utcfromtimestamp(decoded['exp']).isoformat(),
            "scopes": decoded.get('scope', '').split(),
            "email": decoded.get('email')
        }
    except Exception as e:
        return {"error": f"Token decode failed: {str(e)}"}