#!/usr/bin/env python3
"""
Gmail URL Extractor for Phishing Detection

This module automatically extracts URLs from Gmail emails and feeds them
to the phishing detection system for analysis.
"""

import re
import base64
import json
from email.mime.text import MIMEText
from datetime import datetime, timedelta

# Note: These imports would be needed for actual Gmail API integration
# pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client
try:
    from googleapiclient.discovery import build
    from google_auth_oauthlib.flow import InstalledAppFlow
    from google.auth.transport.requests import Request
    import pickle
    import os.path
    GMAIL_API_AVAILABLE = True
except ImportError:
    GMAIL_API_AVAILABLE = False
    print("⚠️ Gmail API libraries not installed. Using demo mode.")
    print("To install: pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client")

from phishing_detector import is_phishing_url, analyze_url_details
from enhanced_detector import EnhancedPhishingDetector


class GmailURLExtractor:
    """Extract URLs from Gmail emails for phishing analysis."""
    
    def __init__(self):
        self.SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
        self.service = None
        self.detector = EnhancedPhishingDetector()
        
    def authenticate_gmail(self):
        """Authenticate with Gmail API."""
        if not GMAIL_API_AVAILABLE:
            return False
            
        creds = None
        # Token file stores the user's access and refresh tokens
        if os.path.exists('token.pickle'):
            with open('token.pickle', 'rb') as token:
                creds = pickle.load(token)
        
        # If there are no (valid) credentials available, let the user log in
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not os.path.exists('credentials.json'):
                    print("❌ credentials.json file not found!")
                    print("📋 To set up Gmail API access:")
                    print("1. Go to https://console.developers.google.com/")
                    print("2. Create a new project or select existing")
                    print("3. Enable Gmail API")
                    print("4. Create credentials (OAuth 2.0)")
                    print("5. Download credentials.json")
                    return False
                    
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json', self.SCOPES)
                creds = flow.run_local_server(port=0)
            
            # Save the credentials for the next run
            with open('token.pickle', 'wb') as token:
                pickle.dump(creds, token)
        
        self.service = build('gmail', 'v1', credentials=creds)
        return True
    
    def extract_urls_from_text(self, text):
        """Extract URLs from text using regex."""
        if not text:
            return []
            
        # Comprehensive URL regex pattern
        url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            r'|(?:www\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}'
        )
        
        urls = url_pattern.findall(text)
        
        # Clean and validate URLs
        cleaned_urls = []
        for url in urls:
            url = url.strip()
            if url and not url.endswith('.'):
                # Add protocol if missing
                if not url.startswith(('http://', 'https://')):
                    url = 'https://' + url
                cleaned_urls.append(url)
        
        return list(set(cleaned_urls))  # Remove duplicates
    
    def get_email_content(self, message_id):
        """Get email content from message ID."""
        if not self.service:
            return None, None
            
        try:
            message = self.service.users().messages().get(
                userId='me', id=message_id, format='full'
            ).execute()
            
            subject = ""
            body = ""
            
            # Get subject
            headers = message['payload'].get('headers', [])
            for header in headers:
                if header['name'] == 'Subject':
                    subject = header['value']
                    break
            
            # Get body
            def extract_body(payload):
                body_text = ""
                if 'parts' in payload:
                    for part in payload['parts']:
                        body_text += extract_body(part)
                else:
                    if payload.get('mimeType') == 'text/plain':
                        data = payload.get('body', {}).get('data')
                        if data:
                            body_text += base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                    elif payload.get('mimeType') == 'text/html':
                        data = payload.get('body', {}).get('data')
                        if data:
                            # For HTML, we'll extract text (simplified)
                            html_content = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                            # Remove HTML tags (basic)
                            clean_text = re.sub('<[^<]+?>', '', html_content)
                            body_text += clean_text
                return body_text
            
            body = extract_body(message['payload'])
            return subject, body
            
        except Exception as e:
            print(f"❌ Error getting email content: {e}")
            return None, None
    
    def get_recent_emails(self, days=7, max_emails=50):
        """Get recent emails from Gmail."""
        if not self.service:
            return []
            
        try:
            # Calculate date for filtering
            date_filter = (datetime.now() - timedelta(days=days)).strftime('%Y/%m/%d')
            query = f'after:{date_filter}'
            
            # Get message list
            results = self.service.users().messages().list(
                userId='me', q=query, maxResults=max_emails
            ).execute()
            
            messages = results.get('messages', [])
            return [msg['id'] for msg in messages]
            
        except Exception as e:
            print(f"❌ Error getting recent emails: {e}")
            return []
    
    def analyze_gmail_urls(self, days=7, max_emails=50):
        """Main function to analyze URLs from Gmail."""
        print("🔍 Gmail URL Phishing Analyzer")
        print("=" * 50)
        
        if not GMAIL_API_AVAILABLE:
            print("📧 Demo Mode: Simulating Gmail URL extraction...")
            return self.demo_mode()
        
        print("🔐 Authenticating with Gmail...")
        if not self.authenticate_gmail():
            print("❌ Gmail authentication failed!")
            return self.demo_mode()
        
        print("✅ Gmail authentication successful!")
        print(f"📧 Fetching emails from last {days} days...")
        
        message_ids = self.get_recent_emails(days, max_emails)
        if not message_ids:
            print("📭 No recent emails found.")
            return
        
        print(f"📧 Found {len(message_ids)} recent emails")
        print("🔍 Extracting and analyzing URLs...")
        
        all_urls = []
        suspicious_emails = []
        
        for i, msg_id in enumerate(message_ids, 1):
            print(f"📧 Processing email {i}/{len(message_ids)}...", end='\r')
            
            subject, body = self.get_email_content(msg_id)
            if not body:
                continue
            
            # Extract URLs from subject and body
            urls = self.extract_urls_from_text(subject + " " + body)
            if urls:
                all_urls.extend(urls)
                
                # Check for suspicious URLs
                suspicious_urls = []
                for url in urls:
                    if is_phishing_url(url):
                        suspicious_urls.append(url)
                
                if suspicious_urls:
                    suspicious_emails.append({
                        'subject': subject,
                        'urls': suspicious_urls,
                        'message_id': msg_id
                    })
        
        print("\n" + "=" * 50)
        self.display_results(all_urls, suspicious_emails)
    
    def demo_mode(self):
        """Demo mode with sample email URLs."""
        print("\n📧 Demo Mode: Analyzing Sample Email URLs")
        print("=" * 50)
        
        # Sample URLs that might be found in emails
        sample_emails = [
            {
                'subject': 'Urgent: Verify Your Account',
                'urls': ['https://bit.ly/verify-account', 'https://secure-bank@phishing.com'],
                'message_id': 'demo_001'
            },
            {
                'subject': 'Meeting Invitation',
                'urls': ['https://zoom.us/meeting/123', 'https://calendar.google.com'],
                'message_id': 'demo_002'
            },
            {
                'subject': 'Special Offer - Click Now!',
                'urls': ['https://tinyurl.com/special-offer', 'https://suspicious-site.com/offer.exe'],
                'message_id': 'demo_003'
            },
            {
                'subject': 'GitHub Notification',
                'urls': ['https://github.com/notifications', 'https://docs.github.com'],
                'message_id': 'demo_004'
            }
        ]
        
        all_urls = []
        suspicious_emails = []
        
        print("🔍 Analyzing sample emails...")
        
        for email in sample_emails:
            print(f"📧 Processing: {email['subject']}")
            
            for url in email['urls']:
                all_urls.append(url)
                if is_phishing_url(url):
                    if email not in suspicious_emails:
                        suspicious_emails.append(email)
        
        print("\n" + "=" * 50)
        self.display_results(all_urls, suspicious_emails)
    
    def display_results(self, all_urls, suspicious_emails):
        """Display analysis results."""
        print("📊 Gmail URL Analysis Results")
        print("=" * 50)
        
        total_urls = len(set(all_urls))
        suspicious_count = len(suspicious_emails)
        
        print(f"📧 Total URLs found: {total_urls}")
        print(f"⚠️ Suspicious emails: {suspicious_count}")
        
        if suspicious_emails:
            print("\n🚨 SUSPICIOUS EMAILS DETECTED:")
            print("=" * 50)
            
            for i, email in enumerate(suspicious_emails, 1):
                print(f"\n{i}. 📧 Subject: {email['subject']}")
                print(f"   📧 Message ID: {email['message_id']}")
                print("   🚨 Suspicious URLs:")
                
                for url in email['urls']:
                    if is_phishing_url(url):
                        print(f"      ⚠️ {url}")
                        
                        # Get detailed analysis
                        analysis = analyze_url_details(url)
                        if analysis['risk_factors']:
                            print("         Risk factors:")
                            for factor in analysis['risk_factors'][:2]:  # Show top 2
                                print(f"           • {factor}")
                print("-" * 30)
        else:
            print("\n✅ No suspicious URLs found in recent emails!")
        
        # Show safe URLs summary
        safe_urls = [url for url in set(all_urls) if not is_phishing_url(url)]
        if safe_urls:
            print(f"\n✅ Safe URLs found: {len(safe_urls)}")
            print("Sample safe URLs:")
            for url in safe_urls[:5]:  # Show first 5
                print(f"   ✅ {url}")
        
        print("\n💡 Recommendations:")
        if suspicious_emails:
            print("   🚨 Review suspicious emails carefully")
            print("   🚫 Do not click on flagged URLs")
            print("   📞 Report suspicious emails to IT security")
            print("   🔒 Verify URLs through official channels")
        else:
            print("   ✅ Your recent emails appear safe")
            print("   🛡️ Continue monitoring for suspicious content")
            print("   📧 Be cautious with unexpected emails")


def interactive_gmail_analyzer():
    """Interactive Gmail URL analyzer."""
    extractor = GmailURLExtractor()
    
    print("🔍 Gmail Phishing URL Analyzer")
    print("=" * 50)
    print("This tool automatically extracts URLs from your Gmail")
    print("and analyzes them for potential phishing threats.")
    print()
    
    while True:
        try:
            print("Options:")
            print("1. 📧 Analyze recent emails (last 7 days)")
            print("2. 📧 Analyze emails from custom period")
            print("3. 🎯 Demo mode (sample data)")
            print("4. ❌ Exit")
            print()
            
            choice = input("Enter your choice (1-4): ").strip()
            
            if choice == '1':
                extractor.analyze_gmail_urls(days=7, max_emails=50)
                
            elif choice == '2':
                try:
                    days = int(input("Enter number of days to analyze (1-30): "))
                    if 1 <= days <= 30:
                        max_emails = int(input("Maximum emails to check (10-100): "))
                        if 10 <= max_emails <= 100:
                            extractor.analyze_gmail_urls(days=days, max_emails=max_emails)
                        else:
                            print("❌ Please enter 10-100 for max emails")
                    else:
                        print("❌ Please enter 1-30 days")
                except ValueError:
                    print("❌ Please enter valid numbers")
                    
            elif choice == '3':
                extractor.demo_mode()
                
            elif choice == '4':
                print("👋 Goodbye!")
                break
                
            else:
                print("❌ Invalid choice. Please enter 1-4.")
            
            # Ask if user wants to continue
            if choice in ['1', '2', '3']:
                continue_choice = input("\nAnalyze more emails? (y/n): ").strip().lower()
                if continue_choice not in ['y', 'yes']:
                    print("👋 Goodbye!")
                    break
                print()
                
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {str(e)}")


if __name__ == "__main__":
    interactive_gmail_analyzer()
