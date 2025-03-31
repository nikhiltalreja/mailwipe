# app.py
from flask import Flask, render_template, request, jsonify, redirect
import imaplib
import ssl
from datetime import datetime, timedelta
import email.utils
import logging
import time
import socket
import re
import uuid
import threading
import urllib.parse
from collections import defaultdict

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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

@app.route('/verify', methods=['POST'])
def verify_connection():
    """Verify IMAP server connection and credentials"""
    start_time = time.time()
    data = request.json
    username = data['username']
    password = data['password']
    
    # Get IMAP server from input
    imap_server = data.get('imap_server')
    if not imap_server:
        return jsonify({"status": "error", "message": "IMAP server is required"})
    
    logger.info(f"Verifying connection for {username} on {imap_server}")
    
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
        mail = imaplib.IMAP4_SSL(imap_server, DEFAULT_IMAP_PORT, ssl_context=context)
        mail.login(username, password)
        
        # Connection successful
        logger.info(f"Connection verified for {username}")
        mail.logout()
        
        return jsonify({
            "status": "success", 
            "message": "Connection verified successfully",
            "time_taken": f"{(time.time() - start_time):.2f} seconds"
        })
    
    except Exception as e:
        logger.error(f"Error verifying connection: {str(e)}", exc_info=True)
        return jsonify({
            "status": "error", 
            "message": str(e)
        })

@app.route('/get_folders', methods=['POST'])
def get_folders():
    """Get list of folders with message counts and sizes"""
    start_time = time.time()
    data = request.json
    username = data['username']
    password = data['password']
    
    # Get IMAP server from input
    imap_server = data.get('imap_server')
    if not imap_server:
        return jsonify({"status": "error", "message": "IMAP server is required"})
    
    logger.info(f"Getting folders for {username} on {imap_server}")
    # Set up more verbose debugging for development
    if app.debug:
        mail_logger = logging.getLogger('imaplib')
        mail_logger.setLevel(logging.DEBUG)
    
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
        mail = imaplib.IMAP4_SSL(imap_server, DEFAULT_IMAP_PORT, ssl_context=context)
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
    username = data['username']
    password = data['password']
    folders = data.get('folders', ['INBOX'])
    
    # Get IMAP server from input
    imap_server = data.get('imap_server')
    if not imap_server:
        return jsonify({"status": "error", "message": "IMAP server is required"})
    
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
        task_id, username, password, imap_server, folders, cutoff_date
    ))
    thread.daemon = True
    thread.start()
    
    # Return task_id immediately for client to poll progress
    return jsonify({
        "status": "success",
        "message": "Cleanup started",
        "task_id": task_id
    })

def process_cleanup(task_id, username, password, imap_server, folders, cutoff_date):
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

if __name__ == '__main__':
    # Make the app accessible on all network interfaces
    app.run(host='0.0.0.0', port=5050, debug=True)