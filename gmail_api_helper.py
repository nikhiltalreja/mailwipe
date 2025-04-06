# gmail_api_helper.py
import imaplib
import logging
import json
import base64 # Added for manual_token_check if needed elsewhere
from datetime import datetime, timedelta, timezone # Added timezone
from typing import Tuple, Optional, Any, List, Dict
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from googleapiclient.errors import HttpError
import time # Added for batch operations

logger = logging.getLogger(__name__)

# Keep full scope, needed for API operations
SCOPES = ['https://mail.google.com/']
GMAIL_API_BATCH_SIZE = 100 # Max 1000 for batchDelete, but smaller batches are safer

class SecureAuth0Credentials(Credentials):
    """Enhanced credential handling with expiration safeguards"""
    def __init__(self, token: str, expires_at_timestamp: float):
        super().__init__(token=token)
        # Ensure expires_at is timezone-aware UTC
        self.expires_at = datetime.fromtimestamp(expires_at_timestamp, tz=timezone.utc)
        self.token = token  # Explicit storage
        logger.info(f"Token initialized, expires: {self.expires_at.isoformat()}")

    def refresh(self, request):
        """Block refresh attempts with clear guidance"""
        logger.warning("Auth0 token refresh attempted via Google library - this is not supported. Initiate reauthentication.")
        # Indicate expiration, prompting re-auth flow
        self.expired = True # Mark as expired
        # Don't raise an exception here, let the 'valid' property handle it
        # raise ValueError("Session expired - please reauthenticate via Auth0")

    @property
    def valid(self) -> bool:
        """Check with 5-minute buffer for token expiration"""
        # Ensure current time is also timezone-aware UTC for comparison
        now_utc = datetime.now(timezone.utc)
        is_valid = bool(self.token) and (now_utc < self.expires_at - timedelta(minutes=5))
        # logger.debug(f"Token validity check: Now={now_utc.isoformat()}, Expires={self.expires_at.isoformat()}, Valid={is_valid}")
        return is_valid

    # Add an explicit expired property check, as refresh doesn't work
    @property
    def expired(self) -> bool:
        return not self.valid

def create_gmail_service(token: str, expires_at: float) -> Tuple[Optional[Any], Optional[str]]:
    """Create Gmail service with expiration validation"""
    try:
        # Check expires_at type - should be a timestamp (float or int)
        if not isinstance(expires_at, (int, float)):
             logger.error(f"Invalid expires_at type: {type(expires_at)}. Expected timestamp.")
             raise TypeError("expires_at must be a valid UNIX timestamp.")
        if expires_at <= 0:
             logger.error(f"Invalid expires_at value: {expires_at}. Must be positive.")
             raise ValueError("expires_at must be a positive timestamp.")

        creds = SecureAuth0Credentials(token, expires_at)
        if not creds.valid:
            logger.warning("Token expired or invalid upon service creation request.")
            # Don't raise ValueError here, return None and error message instead
            return None, "Token expired or invalid - requires reauthentication"

        service = build('gmail', 'v1', credentials=creds, cache_discovery=False)
        logger.info("Gmail API service created successfully.")
        return service, None

    except HttpError as e:
        error_detail = f"HTTP Error {e.resp.status}: {e._get_reason()}"
        logger.error(f"Service creation failed (HttpError): {error_detail}")
        # Check for specific auth errors
        if e.resp.status in [401, 403]:
             return None, f"Authentication/Authorization Error: {e._get_reason()}. Please re-authenticate."
        return None, f"API Error: {error_detail}"
    except Exception as e:
        logger.error(f"Service creation failed (General Exception): {str(e)}", exc_info=True)
        return None, f"Failed to create Gmail service: {str(e)}"

def connect_imap_oauth(email: str, token: str) -> Tuple[Optional[imaplib.IMAP4_SSL], Optional[str]]:
    """IMAP fallback with robust XOAUTH2 handling"""
    try:
        logger.info(f"Attempting IMAP XOAUTH2 connection for {email}")
        imap = imaplib.IMAP4_SSL('imap.gmail.com', 993, timeout=30) # Added timeout
        auth_str = f"user={email}\x01auth=Bearer {token}\x01\x01".encode()
        # Use authenticate method directly
        typ, data = imap.authenticate('XOAUTH2', lambda x: auth_str)
        if typ == 'OK':
            logger.info("IMAP XOAUTH2 authentication successful.")
            return imap, None
        else:
            error_detail = data[0].decode('utf-8') if data and data[0] else "Unknown IMAP authentication error"
            logger.error(f"IMAP XOAUTH2 authentication failed: {typ} - {error_detail}")
            try:
                imap.shutdown() # Clean close
            except:
                pass
            # Check for common token issues
            if "invalid credentials" in error_detail.lower():
                 return None, "IMAP Error: Invalid Credentials. Token might be expired or revoked. Please re-authenticate."
            return None, f"IMAP Authentication Error: {error_detail}"

    except imaplib.IMAP4.error as e:
        error = f"IMAP Protocol Error: {str(e)}. Check token scopes, expiration, and IMAP settings in Gmail."
        logger.error(error)
        return None, error
    except socket.timeout:
        error = "IMAP Error: Connection timed out."
        logger.error(error)
        return None, error
    except Exception as e:
        error = f"IMAP Connection Failed: {str(e)}"
        logger.error(error, exc_info=True)
        return None, error

def verify_gmail_api_connection(service: Any) -> Tuple[bool, str]:
    """Verify Gmail API service by listing labels."""
    if not service:
        return False, "Service object is None"
    try:
        logger.info("Verifying Gmail API connection by listing labels...")
        service.users().labels().list(userId='me').execute()
        logger.info("Gmail API verification successful.")
        return True, "Gmail API verification successful"
    except HttpError as e:
        error_detail = f"HTTP Error {e.resp.status}: {e._get_reason()}"
        logger.error(f"Gmail API verification failed (HttpError): {error_detail}")
        # Provide specific feedback for auth errors
        if e.resp.status == 401:
             return False, f"Authentication Failed: {e._get_reason()}. Token might be invalid or expired."
        if e.resp.status == 403:
             return False, f"Permission Denied: {e._get_reason()}. Check if the API is enabled or token scopes are sufficient."
        return False, f"API Error: {error_detail}"
    except Exception as e:
        logger.error(f"Gmail API verification failed (General Exception): {str(e)}", exc_info=True)
        return False, f"Verification Error: {str(e)}"

# Combined verification function - prioritize API, fallback to IMAP
def verify_connection(email: str, token: str, expires_at: float) -> Tuple[bool, str, str]:
    """
    Comprehensive connection verification. Prioritizes API, falls back to IMAP.
    Returns: (success_bool, message, method_used ('api' or 'imap' or 'failed'))
    """
    # --- Attempt 1: Gmail API ---
    logger.info("Verification attempt: Using Gmail API")
    service, service_error = create_gmail_service(token, expires_at)
    if service:
        api_ok, api_msg = verify_gmail_api_connection(service)
        if api_ok:
            return True, api_msg, "api"
        else:
            # API failed, log the reason but prepare for IMAP fallback
            logger.warning(f"API verification failed: {api_msg}. Will attempt IMAP fallback.")
            service_error = api_msg # Use the more specific error from verification
    elif service_error:
        logger.warning(f"API service creation failed: {service_error}. Will attempt IMAP fallback.")
        # If service creation failed due to auth, don't bother with IMAP
        if "requires reauthentication" in service_error or "Authentication" in service_error or "Permission Denied" in service_error:
            return False, f"Gmail API Failed: {service_error}", "failed"

    # --- Attempt 2: IMAP OAuth Fallback ---
    logger.info("Verification attempt: Falling back to IMAP XOAUTH2")
    imap, imap_error = connect_imap_oauth(email, token)
    if imap:
        try:
            # Perform a basic check like SELECT INBOX
            status, _ = imap.select("INBOX", readonly=True)
            imap.logout()
            if status == 'OK':
                logger.info("IMAP verification successful via SELECT INBOX.")
                return True, "IMAP verification successful (API failed or unavailable)", "imap"
            else:
                logger.warning("IMAP verification failed during SELECT INBOX.")
                imap_error = "IMAP SELECT INBOX failed after successful authentication."
        except Exception as e:
             logger.error(f"Error during IMAP post-auth check: {e}")
             imap_error = f"IMAP post-auth check failed: {e}"

    # --- Final Failure Analysis ---
    error_msg = "All verification methods failed.\n"
    if service_error:
        error_msg += f"- Gmail API: {service_error}\n"
    else:
        error_msg += "- Gmail API: Service creation failed for unknown reason.\n"
    if imap_error:
        error_msg += f"- IMAP: {imap_error}"
    else:
         error_msg += f"- IMAP: Connection or authentication failed for unknown reason."

    logger.error(f"Final Verification Result: Failed. Details:\n{error_msg}")
    return False, error_msg, "failed"

def get_gmail_labels_as_folders(service: Any) -> Tuple[Optional[List[Dict]], Optional[str]]:
    """Gets Gmail labels and formats them like IMAP folders."""
    if not service:
        return None, "Service object is None"
    try:
        logger.info("Fetching Gmail labels via API...")
        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])
        logger.info(f"Retrieved {len(labels)} labels.")

        folders = []
        total_messages = 0
        # Size estimation is tricky with labels, usually requires fetching messages.
        # We will estimate based on message count * average size later if needed,
        # or rely on the user understanding labels != folders size-wise.
        # For now, focus on counts.

        system_labels_map = {
            'INBOX': 'Inbox',
            'SENT': 'Sent',
            'DRAFT': 'Drafts',
            'TRASH': 'Trash',
            'SPAM': 'Spam',
            'IMPORTANT': 'Important',
            'STARRED': 'Starred',
            'UNREAD': 'Unread',
            # Add others if needed
        }

        for label in labels:
            label_id = label['id']
            label_name = label.get('name', label_id) # Use name, fallback to ID

            # Use friendly names for system labels
            display_name = system_labels_map.get(label_id, label_name)

            # Get message count estimate (more reliable than threads)
            # Requires fetching label details individually - might be slow for many labels
            # Alternative: Use counts from list() if sufficient ('messagesTotalEstimate')
            # Let's try fetching details for better accuracy
            try:
                label_details = service.users().labels().get(userId='me', id=label_id).execute()
                # Use messagesTotal - more accurate than messagesUnread
                message_count = label_details.get('messagesTotal', 0)
            except HttpError as e:
                 logger.warning(f"Could not get details for label {label_id} ({label_name}): {e._get_reason()}. Using estimates from list.")
                 # Fallback to estimates from the list() call if get() fails
                 message_count = label.get('messagesTotal', label.get('threadsTotal', 0)) # Prefer messagesTotal estimate


            # Skip labels with no messages? Optional, but common folders often have 0 until used.
            # if message_count == 0:
            #     continue

            folders.append({
                'name': label_id, # Use label ID as the internal name for API calls
                'displayName': display_name,
                'messageCount': message_count,
                'size': 0, # API doesn't provide easy size per label
                'sizeFormatted': "N/A" # Indicate size isn't directly available
            })
            total_messages += message_count

        # Sort: System labels first, then alphabetically by display name
        def sort_key(folder):
            is_system = folder['name'] in system_labels_map
            return (0 if is_system else 1, folder['displayName'].lower())

        folders.sort(key=sort_key)

        logger.info(f"Formatted {len(folders)} labels into folder structure.")
        return folders, None

    except HttpError as e:
        error_detail = f"HTTP Error {e.resp.status}: {e._get_reason()}"
        logger.error(f"Failed to get Gmail labels (HttpError): {error_detail}")
        if e.resp.status in [401, 403]:
             return None, f"Authentication/Authorization Error: {e._get_reason()}."
        return None, f"API Error: {error_detail}"
    except Exception as e:
        logger.error(f"Failed to get Gmail labels (General Exception): {str(e)}", exc_info=True)
        return None, f"Error getting labels: {str(e)}"


def delete_emails_gmail_api(service: Any, query: str, task_id: str, progress_dict: Dict, max_messages_to_delete: int = -1) -> Tuple[int, int, Optional[str]]:
    """
    Deletes emails matching a query using the Gmail API with progress updates.
    Uses batchDelete for efficiency.
    Returns: (total_deleted_count, estimated_size_deleted, error_message)
    max_messages_to_delete: Limit deletion count (-1 for no limit).
    """
    if not service:
        return 0, 0, "Service object is None"
    if not progress_dict or not isinstance(progress_dict, dict):
        return 0, 0, "Invalid progress dictionary provided"

    total_deleted_count = 0
    estimated_size_deleted = 0
    page_token = None
    processed_count_for_progress = 0
    # Get initial estimate for progress calculation (can be inaccurate)
    initial_estimate = 0
    try:
        estimate_result = service.users().messages().list(userId='me', q=query, maxResults=1).execute()
        initial_estimate = estimate_result.get('resultSizeEstimate', 0)
        logger.info(f"Initial estimate for query '{query}': {initial_estimate} messages.")
        if initial_estimate == 0:
             logger.info("Query matches 0 messages based on estimate. Nothing to delete.")
             # Update progress to show completion quickly
             progress_dict["current_folder_progress"] = 100
             return 0, 0, None # Nothing to do
    except HttpError as e:
        error_detail = f"Initial count HttpError {e.resp.status}: {e._get_reason()}"
        logger.error(error_detail)
        return 0, 0, f"API Error during initial count: {error_detail}"
    except Exception as e:
        logger.error(f"Initial count failed: {e}")
        # Proceed cautiously, assuming there might be messages
        initial_estimate = -1 # Indicate unknown estimate

    logger.info(f"Starting Gmail API deletion for query: {query}")

    while True:
        try:
            # Check deletion limit
            if 0 < max_messages_to_delete <= total_deleted_count:
                logger.info(f"Reached deletion limit ({max_messages_to_delete}). Stopping.")
                break

            request = service.users().messages().list(
                userId='me',
                q=query,
                maxResults=GMAIL_API_BATCH_SIZE, # Process in manageable batches
                pageToken=page_token
            )
            response = request.execute()
            messages = response.get('messages', [])

            if not messages:
                logger.info("No more messages found matching the query.")
                break

            message_ids = [msg['id'] for msg in messages]
            batch_size = len(message_ids)

            # Apply deletion limit if needed within this batch
            if max_messages_to_delete > 0:
                 remaining_limit = max_messages_to_delete - total_deleted_count
                 if batch_size > remaining_limit:
                     message_ids = message_ids[:remaining_limit]
                     batch_size = len(message_ids)
                     logger.info(f"Adjusting batch size to meet deletion limit. Processing {batch_size} messages.")


            if not message_ids: # Should not happen if messages list was not empty, but check
                 break

            logger.info(f"Found batch of {batch_size} messages to delete.")

            # --- Estimate size before deleting (Optional but good for progress) ---
            batch_size_bytes = 0
            try:
                # Get size estimates in a single batch request
                batch_get_req = service.new_batch_http_request()
                size_results = []
                
                def size_callback(request_id, response, exception):
                    if exception is None and response:
                        size_results.append(response.get('sizeEstimate', 0))
                    elif exception:
                        logger.warning(f"Error getting size for message in batch: {exception}")
                        size_results.append(0) # Default to 0 if error

                for msg_id in message_ids:
                    batch_get_req.add(
                        service.users().messages().get(
                            userId='me',
                            id=msg_id,
                            fields='sizeEstimate' # Only fetch size estimate
                        ),
                        callback=size_callback
                    )
                
                batch_get_req.execute()
                batch_size_bytes = sum(size_results)
                estimated_size_deleted += batch_size_bytes
                logger.debug(f"Estimated size for batch: {batch_size_bytes} bytes")
            except Exception as size_e:
                logger.warning(f"Could not estimate size for batch: {size_e}. Size reporting will be inaccurate.")
            # --- End Size Estimation ---


            # --- Perform Batch Deletion ---
            logger.info(f"Attempting batchDelete for {batch_size} message IDs...")
            delete_request = service.users().messages().batchDelete(
                userId='me',
                body={'ids': message_ids}
            )
            delete_request.execute()
            # batchDelete returns 204 No Content on success, raises HttpError on failure.
            logger.info(f"Successfully executed batchDelete for {batch_size} messages.")
            total_deleted_count += batch_size
            processed_count_for_progress += batch_size # Increment progress counter

            # Update progress
            progress_dict["total_emails_deleted"] += batch_size
            progress_dict["total_size_deleted"] += batch_size_bytes # Add estimated size

            # Update folder-specific progress (estimate based on initial count if available)
            if initial_estimate > 0:
                 folder_prog = min(100, (processed_count_for_progress / initial_estimate) * 100)
                 progress_dict["current_folder_progress"] = folder_prog
            # logger.debug(f"Progress updated: Deleted {total_deleted_count}, Size: {estimated_size_deleted}, Folder %: {progress_dict['current_folder_progress']:.1f}")


            page_token = response.get('nextPageToken')
            if not page_token:
                logger.info("No nextPageToken found, end of results.")
                break

            # Optional: Add a small delay between batches to avoid rate limits
            time.sleep(0.2)

        except HttpError as e:
            error_detail = f"API HttpError {e.resp.status}: {e._get_reason()}"
            logger.error(f"Error during batchDelete/list: {error_detail}", exc_info=True)
            # Check for rate limiting
            if e.resp.status == 429 or (e.resp.status == 403 and 'rateLimitExceeded' in str(e.content)):
                 logger.warning("Rate limit likely exceeded. Pausing before retry...")
                 time.sleep(5) # Wait 5 seconds
                 # Don't break, let the loop retry the current page_token
                 continue # Skip to next iteration to retry
            # Check for auth errors that require stopping
            elif e.resp.status in [401, 403]:
                 return total_deleted_count, estimated_size_deleted, f"Authentication/Authorization Error: {e._get_reason()}. Stopping cleanup."
            else:
                 # For other errors, log and stop processing this query
                 return total_deleted_count, estimated_size_deleted, f"API Error: {error_detail}"
        except Exception as e:
            logger.error(f"Unexpected error during Gmail API deletion: {str(e)}", exc_info=True)
            return total_deleted_count, estimated_size_deleted, f"Unexpected Error: {str(e)}"

    # Final progress update
    progress_dict["current_folder_progress"] = 100
    logger.info(f"Gmail API deletion completed for query '{query}'. Total deleted: {total_deleted_count}")
    return total_deleted_count, estimated_size_deleted, None

# --- Keep manual_token_check if needed for debugging ---
def manual_token_check(token: str) -> dict:
    """
    DEBUGGING ONLY - Manual token verification (decodes payload without validation)
    
    WARNING: This function is for debugging purposes only and should not be used
    in production code as it does not validate the token signature.
    """
    logger.warning("DEBUG FUNCTION CALLED: manual_token_check - This should not be used in production")
    try:
        # Decode JWT payload without validation
        payload_b64 = token.split('.')[1]
        # Add padding if necessary
        payload_b64 += '=' * (-len(payload_b64) % 4)
        decoded_payload = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
        payload_dict = json.loads(decoded_payload)

        expires_at_str = "N/A"
        if 'exp' in payload_dict:
            try:
                 expires_at_str = datetime.fromtimestamp(payload_dict['exp'], tz=timezone.utc).isoformat()
            except Exception:
                 expires_at_str = f"Invalid timestamp: {payload_dict['exp']}"

        return {
            "expires_at": expires_at_str,
            "issued_at": datetime.fromtimestamp(payload_dict.get('iat', 0), tz=timezone.utc).isoformat() if 'iat' in payload_dict else "N/A",
            "scopes": payload_dict.get('scope', '').split(),
            "email": payload_dict.get('email'),
            "audience": payload_dict.get('aud'),
            "issuer": payload_dict.get('iss'),
            # Add other relevant claims if needed
        }
    except Exception as e:
        logger.error(f"Token decode failed: {str(e)}", exc_info=True)
        return {"error": f"Token decode failed: {str(e)}"}