# EmailWipe

A fast, elegant email cleanup tool that helps you delete old emails in bulk. Zero scanning, zero restrictions.

## Features

- Clean old emails from multiple folders at once
- No message count restrictions - handles 50,000+ emails with ease
- Private & secure - credentials never stored, content never scanned
- Works with all IMAP email providers (Gmail, Outlook, Yahoo, etc.)
- Real-time progress tracking with detailed statistics
- Elegant, responsive UI with dark theme
- Demo mode for trying the app without affecting real emails

## Tech Stack

- **Backend**: Python, Flask
- **Frontend**: HTML, CSS, JavaScript
- **Email Protocol**: IMAP via imaplib

## Development

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run the development server: `python3 app.py`
4. Visit `http://localhost:5000` in your browser

### Demo Mode

The application includes a demo mode that simulates the email cleanup process without actually connecting to any email servers or deleting any emails:

- Access the demo at: `http://localhost:5000/demo`
- The demo mode runs in a separate route with clear indicators that it's a demo
- Users can switch between demo and live modes using links in the UI

## Deployment

This application is ready for deployment on Railway, Heroku, or any other platform that supports Python/Flask applications.

### Railway Deployment

1. Fork this repository
2. Create a new project on Railway
3. Connect your GitHub repository
4. Railway will automatically detect the Python project and deploy it
5. Set up a custom domain (emailwipe.com) in Railway's domain settings

## Author

Created by [Nikhil Talreja](https://x.com/partymapper)

- X/Twitter: [@partymapper](https://x.com/partymapper)
- Instagram: [@nikhiltalrejasocial](https://instagram.com/nikhiltalrejasocial)
- Bug Reports: [GitHub Issues](https://github.com/nikhiltalreja/mailwipe/issues)

## License

MIT License