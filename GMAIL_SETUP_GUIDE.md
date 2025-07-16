# 📧 Gmail Integration Setup Guide

## 🎯 **NEW FEATURE: Automatic URL Extraction from Gmail**

The Phishing URL Detector can now automatically grab URLs from your Gmail emails and analyze them for phishing threats!

## 🚀 **How to Use Gmail Integration**

### **Option 1: Demo Mode (No Setup Required)**
```bash
python test_detector.py
# Choose option 6: Gmail URL Analysis
# Choose option 3: Demo mode
```
**What it does:**
- Uses sample email data
- Shows how the Gmail analysis works
- No Gmail account needed
- Perfect for testing the feature

### **Option 2: Real Gmail Integration (Setup Required)**
```bash
python gmail_url_extractor.py
```
**What it does:**
- Connects to your actual Gmail account
- Extracts URLs from recent emails
- Analyzes them for phishing threats
- Provides detailed security reports

## 🔧 **Gmail API Setup (For Real Gmail Integration)**

### **Step 1: Install Required Libraries**
```bash
pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client
```

### **Step 2: Set Up Google Cloud Project**

1. **Go to Google Cloud Console:**
   - Visit: https://console.developers.google.com/
   - Sign in with your Google account

2. **Create a New Project:**
   - Click "New Project"
   - Name it "Phishing URL Detector"
   - Click "Create"

3. **Enable Gmail API:**
   - Go to "APIs & Services" > "Library"
   - Search for "Gmail API"
   - Click on it and press "Enable"

4. **Create Credentials:**
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth 2.0 Client IDs"
   - Choose "Desktop Application"
   - Name it "Phishing Detector"
   - Click "Create"

5. **Download Credentials:**
   - Click the download button next to your credential
   - Save the file as `credentials.json` in your program folder

### **Step 3: First Run Authentication**
```bash
python gmail_url_extractor.py
```
- A browser window will open
- Sign in to your Gmail account
- Grant permissions to the app
- The program will save your authentication

## 📧 **Gmail Analysis Features**

### **Automatic URL Extraction:**
- Scans email subjects and bodies
- Finds all URLs (http, https, www links)
- Removes duplicates
- Validates URL formats

### **Phishing Detection:**
- Analyzes each URL for suspicious patterns
- Identifies URL shorteners (bit.ly, tinyurl, etc.)
- Detects suspicious characters (@, .exe, etc.)
- Flags potential typosquatting

### **Security Reporting:**
- Lists all suspicious emails
- Shows risk factors for each URL
- Provides security recommendations
- Summarizes safe vs. suspicious URLs

## 🎯 **Usage Examples**

### **Example 1: Recent Email Analysis**
```bash
python test_detector.py
# Choose: 6 (Gmail URL Analysis)
# Choose: 1 (Analyze recent emails)

Result:
📧 Total URLs found: 25
⚠️ Suspicious emails: 2
🚨 SUSPICIOUS EMAILS DETECTED:
1. Subject: "Urgent: Verify Your Account"
   ⚠️ https://bit.ly/verify-account
   Risk factors: Uses URL shortener: bit.ly
```

### **Example 2: Custom Time Period**
```bash
python gmail_url_extractor.py
# Choose: 2 (Custom time period)
# Enter: 14 (days)
# Enter: 100 (max emails)

Result:
📧 Found 87 recent emails
🔍 Extracting and analyzing URLs...
📊 Total URLs found: 156
⚠️ Suspicious emails: 5
```

### **Example 3: Demo Mode**
```bash
python test_detector.py
# Choose: 6 (Gmail URL Analysis)
# Choose: 3 (Demo mode)

Result:
📧 Demo Mode: Analyzing Sample Email URLs
📊 Total URLs found: 8
⚠️ Suspicious emails: 2
```

## 🛡️ **Security & Privacy**

### **What the Program Accesses:**
- ✅ Email subjects and content (read-only)
- ✅ URLs within emails
- ❌ Does NOT store email content
- ❌ Does NOT send data anywhere
- ❌ Does NOT modify emails

### **Authentication:**
- Uses Google's official OAuth 2.0
- Credentials stored locally only
- You can revoke access anytime
- No passwords stored

### **Data Handling:**
- URLs analyzed locally on your computer
- No data sent to external servers
- Results displayed only to you
- No logging of personal information

## 📋 **Menu Integration**

The Gmail analysis is now integrated into the main test suite:

```
🧪 Phishing URL Detector Test Suite
==================================================
1. 🔍 Basic Detector Tests
2. 🚀 Enhanced Detector Tests  
3. 🛡️ Edge Cases & Error Handling
4. 🎯 All Tests (Complete Suite)
5. 📋 Custom Test Selection
6. 📧 Gmail URL Analysis (Auto-grab URLs)  ← NEW!
7. ❌ Exit
```

## 🚀 **Quick Start Commands**

### **Try Demo Mode (No Setup):**
```bash
python test_detector.py
# Choose: 6, then 3
```

### **Set Up Real Gmail Integration:**
```bash
# 1. Install libraries
pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client

# 2. Set up Google Cloud project (see steps above)

# 3. Run the analyzer
python gmail_url_extractor.py
```

### **Standalone Gmail Analysis:**
```bash
python gmail_url_extractor.py
```

## 💡 **Benefits**

1. **Automatic Detection:** No manual URL entry needed
2. **Real-time Analysis:** Check your actual emails
3. **Comprehensive Scanning:** Analyzes multiple emails at once
4. **Security Focused:** Identifies threats in your inbox
5. **User Friendly:** Simple menu-driven interface
6. **Privacy Respecting:** All analysis done locally

## ⚠️ **Troubleshooting**

### **"Gmail API libraries not installed"**
```bash
pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client
```

### **"credentials.json file not found"**
- Follow the Google Cloud setup steps above
- Download credentials.json to your program folder

### **"Gmail authentication failed"**
- Check your internet connection
- Verify credentials.json is correct
- Try deleting token.pickle and re-authenticating

### **"No recent emails found"**
- Check if you have emails in the specified time period
- Try increasing the number of days
- Verify Gmail account has emails

---

## 🎉 **Summary**

**The Phishing URL Detector now automatically grabs URLs from Gmail!**

- ✅ **Automatic URL extraction** from Gmail emails
- ✅ **Real-time phishing analysis** of email URLs
- ✅ **Demo mode** for testing without setup
- ✅ **Integrated into test suite** (option 6)
- ✅ **Privacy-focused** local analysis
- ✅ **User-friendly** menu interface

**Protect yourself from email phishing attacks automatically!** 🛡️
