# OAuth Configuration for EmailWipe

# Google OAuth Configuration
GOOGLE_CLIENT_ID = "YOUR_GOOGLE_CLIENT_ID"
GOOGLE_CLIENT_SECRET = "YOUR_GOOGLE_CLIENT_SECRET"
GOOGLE_REDIRECT_URI = "https://emailwipe.com/auth/google/callback"
GOOGLE_AUTH_SCOPES = ["https://mail.google.com/"]

# Microsoft OAuth Configuration
MICROSOFT_CLIENT_ID = "YOUR_MICROSOFT_CLIENT_ID"
MICROSOFT_CLIENT_SECRET = "YOUR_MICROSOFT_CLIENT_SECRET"
MICROSOFT_REDIRECT_URI = "https://emailwipe.com/auth/microsoft/callback"
MICROSOFT_AUTH_SCOPES = ["https://outlook.office.com/IMAP.AccessAsUser.All", "offline_access"]

# Add this file to .gitignore to keep credentials secure