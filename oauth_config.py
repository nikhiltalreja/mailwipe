# OAuth Configuration for EmailWipe

# Auth0 Configuration - Free tier supports 7,000 MAU (Monthly Active Users)
AUTH0_DOMAIN = "dev-khykkdf6d4gtrz1y.us.auth0.com"
AUTH0_CLIENT_ID = "eNPThhTMZmjmc3z4iwdxSzf24TaDItsc" 
AUTH0_CLIENT_SECRET = "rcGFLKlXmkj6qH5iScGYwQSx-DNW9NSyrNMv1MPFhmZPwD_EzVDwjc3MhA7kJw7u"

# Make sure this exactly matches the URL configured in Auth0 dashboard
# If testing locally, use http://localhost:5050/auth/callback
# For production, use the Railway URL
AUTH0_CALLBACK_URL = "https://web-production-99c5.up.railway.app/auth/callback"

# IMPORTANT CONFIGURATION NOTES:
# 1. In Auth0 dashboard, set the application type to "Regular Web Application"
# 2. Set the Token Endpoint Authentication Method to "POST" (not Basic)
# 3. Enable the following Grant Types: Authorization Code, Refresh Token
# 4. Add the callback URL exactly as shown above
# 5. For Gmail login:
#    - Add Google OAuth2 as a Social Connection
#    - In the Google connection settings, make sure all required scopes are enabled
#    - In the Google Cloud Console, add the Auth0 domain to the authorized domains
#    - Use the correct OAuth Client ID and Secret from Google for your Auth0 connection
# 6. Verify Allowed Callback URLs in your Auth0 Application Settings includes the exact callback URL

# Default IMAP servers for providers
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

# Add this file to .gitignore to keep credentials secure