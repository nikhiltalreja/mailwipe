#!/bin/bash
# Debug startup script for EmailWipe

echo "Starting EmailWipe in debug mode with enhanced logging..."
echo "$(date): Starting application" > debug_startup.log

# Enable all Flask debug options
export FLASK_DEBUG=1
export PYTHONUNBUFFERED=1
export LOG_LEVEL=DEBUG

# Run with redirected output for complete logs
python3 app.py 2>&1 | tee -a debug_startup.log

echo "Application terminated. Check debug_startup.log for details."