#!/usr/bin/env python3
"""
Updated Gmail API Helper with Full Access Scope
Version: 1.1 - Enhanced token handling for Auth0
"""

import os
import logging
from typing import List, Dict, Any, Optional, Tuple
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)

# Full access scope
SCOPES = ['https://mail.google.com/']

class NonRefreshingCredentials(Credentials):
    """Credentials that never refresh - optimized for Auth0 tokens"""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._refresh_token = "dummy"
        self._token_uri = "https://oauth2.googleapis.com/token"
        self._client_id = "dummy"
        self._client_secret = "dummy"
        
    def refresh(self, request):
        raise ValueError("Refresh not supported with Auth0 tokens")
        
    @property
    def expired(self):
        return False

def validate_auth0_token(access_token: str) -> bool:
    """Validate that an Auth0 token has the required Gmail scopes"""
    try:
        # Decode the token to check scopes (middle part between .s)
        parts = access_token.split('.')
        if len(parts) != 3:
            return False
            
        import base64
        import json
        # Add padding if needed and decode
        payload = parts[1] + '=' * (-len(parts[1]) % 4)
        decoded = json.loads(base64.b64decode(payload).decode('utf-8'))
        
        # Check if our required scopes are present
        token_scopes = decoded.get('scope', '').split()
        required_scopes = set(SCOPES)
        
        return required_scopes.issubset(set(token_scopes))
        
    except Exception as e:
        logger.error(f"Token validation error: {str(e)}")
        return False

def validate_gmail_scope(access_token: str) -> bool:
    """Verify the token has the required Gmail scope"""
    try:
        import jwt
        decoded = jwt.decode(access_token, options={"verify_signature": False})
        return 'https://mail.google.com/' in decoded.get('scope', '').split()
    except Exception as e:
        logger.error(f"Scope validation failed: {str(e)}")
        return False

def create_gmail_service(access_token: str) -> Tuple[Any, Optional[str]]:
    """Create authenticated Gmail service"""
    if not validate_gmail_scope(access_token):
        return None, "Missing required Gmail permissions"
    
    try:
        creds = NonRefreshingCredentials(token=access_token)
        service = build('gmail', 'v1', credentials=creds, 
                       cache_discovery=False, static_discovery=False)
        return service, None
    except Exception as e:
        logger.error(f"Service creation failed: {str(e)}")
        return None, str(e)

def verify_gmail_connection(access_token: str) -> Tuple[bool, Optional[str]]:
    """Verify connection to Gmail API using Auth0 token"""
    try:
        # First validate the token format
        if not validate_auth0_token(access_token):
            return False, "Invalid token or missing required Gmail scopes"
            
        # Then proceed with API test
        service, error = create_gmail_service(access_token)
        if not service:
            return False, error
            
        # Minimal API call that doesn't require special permissions
        try:
            service.users().getProfile(userId='me').execute()
            return True, None
        except HttpError as error:
            if error.resp.status == 403:
                return False, "Insufficient permissions - ensure all required scopes are granted"
            return False, f"API error: {error.reason}"
            
    except Exception as e:
        return False, f"Connection error: {str(e)}"
        
def get_gmail_folders(access_token: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """
    Get list of Gmail folders/labels.
    
    Args:
        access_token: OAuth access token
        
    Returns:
        Tuple of (list of folder objects, error message or None if success)
    """
    try:
        # Create Gmail service
        service, error = create_gmail_service(access_token)
        if not service:
            return [], error
        
        try:
            # Get labels (Gmail's equivalent of folders)
            results = service.users().labels().list(userId='me').execute()
            labels = results.get('labels', [])
            
            # Format labels to match the format expected by EmailWipe
            folders = []
            
            if not labels:
                logger.info('No labels found')
                return [], None
            
            logger.info(f"Found {len(labels)} Gmail labels")
            
            # Process each label
            for label in labels:
                # Skip system labels we don't want to show
                if label['type'] == 'system' and label['id'] in ['CATEGORY_PROMOTIONS', 'CATEGORY_SOCIAL', 'CATEGORY_UPDATES', 'CATEGORY_FORUMS']:
                    continue
                    
                try:
                    # Get details for this label
                    label_details = service.users().labels().get(userId='me', id=label['id']).execute()
                    
                    # Get message count and size
                    message_count = label_details.get('messagesTotal', 0)
                    size = label_details.get('messagesUnreadTotal', 0)  # This isn't the actual size, but we don't have that via API
                    
                    folder = {
                        'name': label['id'],  # Use ID for operations
                        'displayName': label['name'],  # Use name for display
                        'messageCount': message_count,
                        'size': size * 10000,  # Rough estimate since API doesn't provide size
                        'sizeFormatted': f"{(size * 10000) / (1024 * 1024):.1f} MB" # Rough estimate
                    }
                    
                    folders.append(folder)
                except Exception as label_error:
                    logger.warning(f"Error processing label {label.get('id', 'unknown')}: {str(label_error)}")
                    # Continue processing other labels
            
            return folders, None
            
        except HttpError as error:
            # Handle API-specific errors
            error_message = f"Gmail API error: {error.reason if hasattr(error, 'reason') else str(error)}"
            logger.error(error_message)
            
            # Check for specific error types
            if hasattr(error, 'resp') and error.resp.status == 401:
                logger.warning("OAuth token appears to be expired or invalid")
                return [], "Authentication failed. Please re-authenticate with Google."
            elif hasattr(error, 'resp') and error.resp.status == 403:
                return [], "Permission denied. The requested scopes may not be authorized."
            else:
                return [], error_message
    
    except Exception as e:
        error_message = f"Error getting Gmail folders: {str(e)}"
        logger.error(error_message)
        
        # Handle refresh token errors specifically
        if "refresh" in str(e).lower():
            return [], "The OAuth token does not support refreshing. Please re-authenticate with Google."
        
        return [], error_message

def delete_gmail_messages(access_token: str, label_id: str, max_results: int = 100) -> Tuple[int, Optional[str]]:
    """
    Delete messages from a Gmail label.
    
    Args:
        access_token: OAuth access token
        label_id: Gmail label ID to delete from
        max_results: Maximum number of messages to delete
        
    Returns:
        Tuple of (number of deleted messages, error message or None if success)
    """
    try:
        # Create Gmail service
        service, error = create_gmail_service(access_token)
        if not service:
            return 0, error
        
        try:
            # Get message IDs for the label
            results = service.users().messages().list(
                userId='me', 
                labelIds=[label_id],
                maxResults=max_results
            ).execute()
            
            messages = results.get('messages', [])
            
            if not messages:
                return 0, None
            
            # Batch delete messages
            deleted_count = 0
            for message in messages:
                try:
                    service.users().messages().trash(userId='me', id=message['id']).execute()
                    deleted_count += 1
                except Exception as msg_error:
                    logger.warning(f"Error deleting message {message['id']}: {str(msg_error)}")
                    # Continue with other messages
            
            return deleted_count, None
            
        except HttpError as error:
            # Handle API-specific errors
            error_message = f"Gmail API error: {error.reason if hasattr(error, 'reason') else str(error)}"
            logger.error(error_message)
            
            # Check for specific error types
            if hasattr(error, 'resp') and error.resp.status == 401:
                logger.warning("OAuth token appears to be expired or invalid")
                return 0, "Authentication failed. Please re-authenticate with Google."
            elif hasattr(error, 'resp') and error.resp.status == 403:
                return 0, "Permission denied. The requested scopes may not be authorized."
            else:
                return 0, error_message
        
    except Exception as e:
        error_message = f"Error deleting Gmail messages: {str(e)}"
        logger.error(error_message)
        
        # Handle refresh token errors specifically
        if "refresh" in str(e).lower():
            return 0, "The OAuth token does not support refreshing. Please re-authenticate with Google."
        
        return 0, error_message

if __name__ == "__main__":
    # This is for testing the module directly
    print("Gmail API Helper Module - Run tests here")