# OAuth Configuration for EmailWipe

# Auth0 Configuration - Free tier supports 7,000 MAU (Monthly Active Users)
AUTH0_DOMAIN = "YOUR_AUTH0_DOMAIN.auth0.com"
AUTH0_CLIENT_ID = "YOUR_AUTH0_CLIENT_ID" 
AUTH0_CLIENT_SECRET = "YOUR_AUTH0_CLIENT_SECRET"
AUTH0_CALLBACK_URL = "https://emailwipe.com/auth/callback"

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