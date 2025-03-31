# OAuth Configuration for EmailWipe

# Auth0 Configuration - Free tier supports 7,000 MAU (Monthly Active Users)
AUTH0_DOMAIN = "dev-khykkdf6d4gtrz1y.us.auth0.com"
AUTH0_CLIENT_ID = "eNPThhTMZmjmc3z4iwdxSzf24TaDItsc" 
AUTH0_CLIENT_SECRET = "rcGFLKlXmkj6qH5iScGYwQSx-DNW9NSyrNMv1MPFhmZPwD_EzVDwjc3MhA7kJw7u"
AUTH0_CALLBACK_URL = "https://web-production-99c5.up.railway.app/auth/callback"

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