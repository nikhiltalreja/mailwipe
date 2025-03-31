#!/usr/bin/env python3
"""
Gmail API Helper Module for EmailWipe

This module provides functions to interact with Gmail using the Gmail API
instead of IMAP. This is a more reliable approach for Gmail accounts.
"""

import os
import logging
import base64
from typing import List, Dict, Any, Optional, Tuple

# Gmail API libraries
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request

# Configure logging
logger = logging.getLogger(__name__)

# Gmail API scopes needed
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Custom credentials class that never attempts to refresh
class NonRefreshingCredentials(Credentials):
    """Custom credentials class that never attempts to refresh.
    This is useful when we only have an access token without refresh capabilities."""
    
    def refresh(self, request):
        """Override the refresh method to do nothing"""
        logger.warning("Refresh attempted but ignored by NonRefreshingCredentials")
        pass
        
    @property
    def expired(self):
        """Override to always return False so refresh is never attempted"""
        return False

def create_gmail_service(access_token: str) -> Tuple[Any, Optional[str]]:
    """
    Create a Gmail API service using an access token.
    
    Args:
        access_token: OAuth access token from Auth0
        
    Returns:
        Tuple of (service object or None if error, error message or None if success)
    """
    try:
        logger.info("Creating Gmail API service")
        # Create our custom credentials object from access token
        # This credentials object will never attempt to refresh
        creds = NonRefreshingCredentials(
            token=access_token,
            scopes=SCOPES
        )
        
        # Build the Gmail API service with disable_cache=True to avoid cache issues
        service = build('gmail', 'v1', credentials=creds, cache_discovery=False)
        return service, None
    
    except HttpError as error:
        error_message = f"Gmail API error: {error.reason if hasattr(error, 'reason') else str(error)}"
        logger.error(error_message)
        return None, error_message
    
    except Exception as e:
        error_message = f"Error creating Gmail service: {str(e)}"
        logger.error(error_message)
        return None, error_message

def verify_gmail_connection(access_token: str) -> Tuple[bool, Optional[str]]:
    """
    Verify connection to Gmail API using the given access token.
    
    Args:
        access_token: OAuth access token
        
    Returns:
        Tuple of (success boolean, error message or None if success)
    """
    try:
        # Create Gmail service
        service, error = create_gmail_service(access_token)
        if not service:
            return False, error
        
        # Make a simple API call to test the connection
        # Get user profile to verify the token works
        try:
            profile = service.users().getProfile(userId='me').execute()
            
            if profile and 'emailAddress' in profile:
                logger.info(f"Successfully verified Gmail API connection for {profile['emailAddress']}")
                return True, None
            else:
                logger.warning("Gmail API connection verified but couldn't get email address")
                return True, None
                
        except HttpError as error:
            # Handle API-specific errors
            error_message = f"Gmail API error: {error.reason if hasattr(error, 'reason') else str(error)}"
            logger.error(error_message)
            
            # Check for specific error types
            if hasattr(error, 'resp') and error.resp.status == 401:
                logger.warning("OAuth token appears to be expired or invalid")
                return False, "Authentication failed. Please re-authenticate with Google."
            elif hasattr(error, 'resp') and error.resp.status == 403:
                return False, "Permission denied. The requested scopes may not be authorized."
            else:
                return False, error_message
    
    except Exception as e:
        error_message = f"Error verifying Gmail connection: {str(e)}"
        logger.error(error_message)
        
        # Handle refresh token errors specifically
        if "refresh" in str(e).lower():
            return False, "The OAuth token does not support refreshing. Please re-authenticate with Google."
        
        return False, error_message

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