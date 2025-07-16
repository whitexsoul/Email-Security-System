#!/usr/bin/env python3
"""
Phishing URL Detector

A simple tool to detect potentially malicious URLs based on common phishing patterns.
This tool uses heuristic analysis to identify suspicious characteristics in URLs.

Author: Phishing Detection Project
Version: 1.0
"""

import re
from urllib.parse import urlparse


def is_phishing_url(url):
    """
    Analyze a URL for common phishing indicators.

    Args:
        url (str): The URL to analyze

    Returns:
        bool: True if the URL appears suspicious, False otherwise
    """
    if not url or not str(url).strip():
        return True

    # Convert URL to lowercase for case-insensitive comparison
    url_lower = url.lower()

    # List of URL shortening services (suspicious)
    url_shorteners = [
        'tinyurl.com', 'bit.ly', 'goo.gl', 't.co', 'ow.ly',
        'tiny.cc', 'is.gd', 'buff.ly'
    ]

    # List of suspicious characters/patterns
    suspicious_chars = ['@', '==', '0x', '%00', '.exe']

    # Check for excessive periods (subdomains) - more than 3 periods is suspicious
    # But also check for suspicious domain patterns like example.com.abc.def
    if url.count('.') > 3:
        return True

    # Check for suspicious domain patterns (multiple TLD-like segments)
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        # Remove www. prefix for analysis
        if domain.startswith('www.'):
            domain = domain[4:]

        # Check for patterns like example.com.abc.def (multiple .xxx segments)
        parts = domain.split('.')
        if len(parts) >= 4:  # domain.com.abc.def has 4 parts
            return True
    except Exception:
        pass

    # Check for URL shorteners (more precise matching)
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()

        for shortener in url_shorteners:
            # Check if the domain exactly matches or ends with the shortener
            if domain == shortener or domain.endswith('.' + shortener):
                return True
    except Exception:
        # If URL parsing fails, fall back to simple string matching
        for shortener in url_shorteners:
            if shortener in url_lower:
                return True

    # Check for suspicious characters
    for char in suspicious_chars:
        if char in url_lower:
            return True

    # Check for suspicious patterns
    if check_suspicious_patterns(url):
        return True

    return False


def check_suspicious_patterns(url):
    """
    Check for additional suspicious patterns in the URL.

    Args:
        url (str): The URL to analyze

    Returns:
        bool: True if suspicious patterns are found
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()

        # Check for IP addresses instead of domain names
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        if re.match(ip_pattern, domain):
            return True

        # Check for suspicious domain patterns
        suspicious_patterns = [
            r'[0-9]+[a-z]+[0-9]+',  # Mixed numbers and letters
            r'[a-z]+-[a-z]+-[a-z]+',  # Multiple hyphens
            r'[a-z]+\d+[a-z]+',  # Letters-numbers-letters pattern
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, domain):
                return True

        # Check for very long domains (potential typosquatting)
        if len(domain) > 50:
            return True

        return False

    except Exception:
        # If URL parsing fails, consider it suspicious
        return True


def analyze_url_details(url):
    """
    Provide detailed analysis of the URL.

    Args:
        url (str): The URL to analyze

    Returns:
        dict: Dictionary containing analysis details
    """
    analysis = {
        'url': url,
        'is_suspicious': False,
        'risk_factors': [],
        'domain_info': {},
        'recommendations': []
    }

    try:
        parsed_url = urlparse(url)
        analysis['domain_info'] = {
            'scheme': parsed_url.scheme,
            'domain': parsed_url.netloc,
            'path': parsed_url.path,
            'query': parsed_url.query
        }

        # Check various risk factors

        # URL shorteners (more precise matching)
        shorteners = ['tinyurl.com', 'bit.ly', 'goo.gl', 't.co', 'ow.ly', 'tiny.cc', 'is.gd', 'buff.ly']
        domain = parsed_url.netloc.lower()
        for shortener in shorteners:
            if domain == shortener or domain.endswith('.' + shortener):
                analysis['risk_factors'].append(f"Uses URL shortener: {shortener}")

        # Suspicious characters
        suspicious_chars = ['@', '==', '0x', '%00', '.exe']
        for char in suspicious_chars:
            if char in url:
                analysis['risk_factors'].append(f"Contains suspicious character/pattern: {char}")

        # Check for excessive periods or suspicious domain patterns
        if url.count('.') > 3:
            analysis['risk_factors'].append(f"Excessive subdomains ({url.count('.')} periods)")
        else:
            # Check for suspicious domain patterns like example.com.abc.def
            domain_parts = parsed_url.netloc.lower().replace('www.', '').split('.')
            if len(domain_parts) >= 4:
                analysis['risk_factors'].append(f"Suspicious domain structure ({len(domain_parts)} segments)")

        # IP address instead of domain
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        if re.search(ip_pattern, parsed_url.netloc):
            analysis['risk_factors'].append("Uses IP address instead of domain name")

        # Very long domain
        if len(parsed_url.netloc) > 50:
            analysis['risk_factors'].append("Unusually long domain name")

        # Set overall suspicion level
        analysis['is_suspicious'] = len(analysis['risk_factors']) > 0

        # Provide recommendations
        if analysis['is_suspicious']:
            analysis['recommendations'] = [
                "Do not enter personal information on this site",
                "Verify the URL with the official website",
                "Check for HTTPS and valid certificates",
                "Use antivirus software to scan the link"
            ]
        else:
            analysis['recommendations'] = [
                "URL appears safe based on basic checks",
                "Always verify HTTPS and certificates",
                "Be cautious with personal information"
            ]

    except Exception as e:
        analysis['risk_factors'].append(f"URL parsing error: {str(e)}")
        analysis['is_suspicious'] = True

    return analysis


def main():
    """
    Main function to run the phishing URL detector interactively.
    """
    print("🔍 Phishing URL Detector")
    print("=" * 40)
    print("This tool helps identify potentially malicious URLs.")
    print("Enter 'quit' to exit the program.\n")

    while True:
        try:
            # Get user input
            url = input("Enter a URL to check: ").strip()

            # Check for exit commands
            if url.lower() in ['quit', 'exit', 'q']:
                print("👋 Goodbye!")
                break

            # Validate input
            if not url:
                print("❌ Please enter a valid URL.\n")
                continue

            # Add protocol if missing
            if not url.startswith(('http://', 'https://')):
                print(f"ℹ️  Adding https:// to URL: {url}")
                url = 'https://' + url

            print(f"\n🔍 Analyzing: {url}")

            # Basic check
            if is_phishing_url(url):
                print("⚠️  WARNING: This might be a phishing URL!")
            else:
                print("✅ Looks safe (based on simple rules).")

            # Detailed analysis
            print("\n📊 Detailed Analysis:")
            analysis = analyze_url_details(url)

            if analysis['risk_factors']:
                print("🚨 Risk Factors Found:")
                for factor in analysis['risk_factors']:
                    print(f"  • {factor}")
            else:
                print("✅ No obvious risk factors detected.")

            print("\n💡 Recommendations:")
            for rec in analysis['recommendations']:
                print(f"  • {rec}")

            print("\n" + "-" * 40 + "\n")

        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except EOFError:
            print("\n\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error analyzing URL: {str(e)}\n")


if __name__ == "__main__":
    main()
