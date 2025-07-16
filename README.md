# 🔍 Phishing URL Detector

A Python tool for detecting potentially malicious URLs that may lead to phishing websites. This project provides both basic and enhanced detection capabilities using heuristic analysis to identify suspicious characteristics in URLs.

## 🚀 Features

### Basic Detector (`phishing_detector.py`)
- **Interactive CLI**: User-friendly command-line interface
- **Pattern Recognition**: Detects common phishing indicators
- **URL Shortener Detection**: Identifies known URL shortening services
- **Suspicious Character Analysis**: Flags URLs with potentially malicious characters
- **Subdomain Analysis**: Detects excessive subdomains that may indicate phishing

### Enhanced Detector (`enhanced_detector.py`)
- **Advanced Risk Scoring**: Comprehensive risk assessment with numerical scores (0-100)
- **Domain Analysis**: Deep analysis of domain characteristics
- **Typosquatting Detection**: Identifies domains that mimic legitimate websites
- **URL Structure Analysis**: Examines URL components for suspicious patterns
- **Batch Processing**: Analyze multiple URLs simultaneously

## 🛠️ Installation

1. **Ensure Python 3.6+ is installed**
2. **No additional dependencies required** - uses only Python standard library

```bash
# Run the programs directly
python phishing_detector.py
python enhanced_detector.py
```

## 📖 Usage

### Basic Detector (Interactive)
```bash
python phishing_detector.py
```
- Enter URLs to check (e.g., `google.com`, `bit.ly/test`)
- Type `quit` to exit
- Automatically adds `https://` if missing

**Example:**
```
Enter a URL to check: bit.ly/suspicious
⚠️  WARNING: This might be a phishing URL!
🚨 Risk Factors Found: Uses URL shortener: bit.ly
```

### Enhanced Detector (Advanced)
```bash
python enhanced_detector.py
```
- Enter URLs for detailed analysis
- Type `batch` for multiple URLs
- Type `help` for commands
- Type `quit` to exit

**Example:**
```
Enter command or URL: bit.ly/test
Risk Level: MEDIUM (Score: 35/100)
⚠️ SUSPICIOUS URL DETECTED
```

### Gmail URL Analysis (NEW!)
```bash
python test_detector.py
# Choose option 6: Gmail URL Analysis
```
- **Automatically extracts URLs from Gmail emails**
- **Analyzes them for phishing threats**
- **Demo mode available (no Gmail setup required)**
- **Real Gmail integration with API setup**

**Example:**
```
📧 Total URLs found: 25
⚠️ Suspicious emails: 2
🚨 Subject: "Urgent: Verify Your Account"
   ⚠️ https://bit.ly/verify-account
```

## 🧪 Testing

### Interactive Test Selection
```bash
python test_detector.py
```

**Choose from:**
- **1. Basic Detector Tests** (5 tests) - Core functionality
- **2. Enhanced Detector Tests** (7 tests) - Advanced features
- **3. Edge Cases Tests** (4 tests) - Error handling
- **4. All Tests** (16 tests) - Complete suite
- **5. Custom Selection** - Pick individual tests
- **6. Exit**

**Example:**
```
🧪 Phishing URL Detector Test Suite
Select which tests to run:
Enter your choice (1-6): 1

Running Basic Detector Tests...
✅ All 5 tests passed!
```

## 🔍 Detection Methods

### What it Detects:
- **URL Shorteners**: bit.ly, tinyurl.com, goo.gl, t.co, etc.
- **Suspicious Characters**: @, %00, .exe, ==, 0x
- **Excessive Subdomains**: More than 3 periods in domain
- **IP Addresses**: URLs using IP addresses instead of domains
- **Typosquatting**: Domains similar to legitimate websites

## 📊 Risk Levels (Enhanced Detector)

| Risk Level | Score | Description |
|------------|-------|-------------|
| MINIMAL    | 0-9   | Very low risk, appears safe |
| LOW        | 10-29 | Some minor indicators |
| MEDIUM     | 30-49 | Multiple risk factors |
| HIGH       | 50-69 | Significant risk |
| CRITICAL   | 70-100| Severe risk, likely malicious |

## 🛡️ Security Tips

- **Never enter personal information** on flagged URLs
- **Verify URLs** through official channels
- **Be cautious with shortened URLs**
- **Check for HTTPS** and valid certificates

## � Files Included

- `phishing_detector.py` - Main interactive detector
- `enhanced_detector.py` - Advanced detector with risk scoring
- `test_detector.py` - Comprehensive test suite
- `requirements.txt` - Dependencies (none required)
- `README.md` - This documentation

## ⚠️ Disclaimer

This tool provides heuristic-based detection and may produce false positives or miss sophisticated phishing attempts. Use as part of a comprehensive security strategy.

---

**Version**: 2.0 | **Python**: 3.6+ | **Dependencies**: None
