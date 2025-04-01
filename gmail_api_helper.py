#!/usr/bin/env python3
"""
Gmail API Helper with IMAP Fallback (Full Scope)
Version: 2.0 - Auth0 Integration with Dual Authentication Paths
"""

import imaplib
import logging
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)

# Full access scope for testing (keep for now)
SCOPES = ['https://mail.google.com/']

class NonRefreshingCredentials(Credentials):
    """Enhanced credentials with expiry tracking"""
    def __init__(self, token: str, expires_in: int = 3600):
        super().__init__(
            token=token,
            refresh_token="auth0_dummy_refresh",
            token_uri="https://oauth2.googleapis.com/token",
            client_id="auth0_dummy_client",
            client_secret="auth0_dummy_secret",
            scopes=SCOPES
        )
        self._expiry = datetime.utcnow() + timedelta(seconds=expires_in)
        
    def refresh(self, request):
        logger.error("Refresh attempted on non-refreshable token")
        raise ValueError("Reauthenticate through Auth0 instead")

    @property
    def valid(self) -> bool:
        return bool(self.token) and datetime.utcnow() < self._expiry

def verify_gmail_connection(access_token: str) -> Tuple[bool, str]:
    """Verify Gmail API connectivity with full scope"""
    try:
        creds = NonRefreshingCredentials(access_token)
        service = build('gmail', 'v1', credentials=creds, cache_discovery=False)
        service.users().labels().list(userId='me').execute()
        return True, "Gmail API connection successful"
    except HttpError as e:
        error_msg = f"Gmail API Error ({e.resp.status}): {e._get_reason()}"
        return False, error_msg
    except Exception as e:
        return False, f"General API error: {str(e)}"

def imap_oauth_connect(email: str, access_token: str) -> Optional[imaplib.IMAP4_SSL]:
    """IMAP fallback with XOAUTH2 authentication"""
    try:
        imap = imaplib.IMAP4_SSL('imap.gmail.com', 993)
        auth_string = f"user={email}\x01auth=Bearer {access_token}\x01\x01"
        imap.authenticate('XOAUTH2', lambda x: auth_string.encode())
        return imap
    except Exception as e:
        logger.error(f"IMAP fallback failed: {str(e)}")
        return None

def verify_connection(email: str, access_token: str) -> bool:
    """Dual verification system with fallback"""
    # Try Gmail API first
    api_success, _ = verify_gmail_connection(access_token)
    if api_success:
        logger.info("Gmail API verification succeeded")
        return True
    
    # Fallback to IMAP OAuth
    logger.warning("Falling back to IMAP authentication")
    imap = imap_oauth_connect(email, access_token)
    if imap:
        imap.logout()
        logger.info("IMAP verification succeeded")
        return True
    
    logger.error("All authentication methods failed")
    return False

def batch_cleanup(access_token: str, email: str, query: str = "older_than:1y") -> dict:
    """Unified cleanup with dual authentication support"""
    try:
        # First try Gmail API
        creds = NonRefreshingCredentials(access_token)
        service = build('gmail', 'v1', credentials=creds)
        messages = service.users().messages().list(
            userId='me', q=query, maxResults=500).execute().get('messages', [])
        
        if messages:
            service.users().messages().batchDelete(
                userId='me', body={'ids': [m['id'] for m in messages]}
            ).execute()
            return {'method': 'api', 'count': len(messages), 'error': None}
            
    except Exception as api_error:
        logger.warning(f"Gmail API failed: {str(api_error)} - Trying IMAP")
        
        # IMAP Fallback
        try:
            imap = imap_oauth_connect(email, access_token)
            if not imap:
                raise ConnectionError("IMAP connection failed")
                
            imap.select('INBOX')
            status, data = imap.search(None, query.replace('_than:', ' '))
            if status == 'OK':
                message_ids = data[0].split()
                if message_ids:
                    imap.store(','.join(m.decode() for m in message_ids), '+FLAGS', '\\Deleted')
                    imap.expunge()
                    return {'method': 'imap', 'count': len(message_ids), 'error': None}
            return {'method': 'imap', 'count': 0, 'error': 'No messages found'}
            
        except Exception as imap_error:
            return {'method': 'failed', 'count': 0, 
                    'error': f"API: {api_error} | IMAP: {imap_error}"}

    return {'method': 'noop', 'count': 0, 'error': 'No messages processed'}

# Example usage
if __name__ == "__main__":
    # Test with Auth0 token
    access_token = "your_auth0_access_token"
    email = "user@example.com"
    
    if verify_connection(email, access_token):
        result = batch_cleanup(access_token, email)
        print(f"Deleted {result['count']} emails via {result['method']}")
    else:
        print("All authentication methods failed")