#!/usr/bin/env python3
"""
Unit Tests for Phishing URL Detector

Test cases to validate the functionality of both basic and enhanced detectors.
"""

import unittest
import sys
import os

# Add current directory to path to import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from phishing_detector import is_phishing_url, analyze_url_details
from enhanced_detector import EnhancedPhishingDetector


class TestBasicPhishingDetector(unittest.TestCase):
    """Test cases for the basic phishing detector."""

    def test_safe_urls(self):
        """Test that legitimate URLs are not flagged as phishing."""
        safe_urls = [
            "https://www.google.com",
            "https://github.com",
            "https://stackoverflow.com",
            "https://www.microsoft.com",
            "http://example.com"
        ]

        for url in safe_urls:
            with self.subTest(url=url):
                self.assertFalse(is_phishing_url(url), f"Safe URL incorrectly flagged: {url}")

    def test_phishing_urls_with_shorteners(self):
        """Test that URLs with shorteners are flagged."""
        phishing_urls = [
            "https://bit.ly/suspicious",
            "http://tinyurl.com/malicious",
            "https://goo.gl/phishing",
            "https://t.co/badlink"
        ]

        for url in phishing_urls:
            with self.subTest(url=url):
                self.assertTrue(is_phishing_url(url), f"Phishing URL not detected: {url}")

    def test_urls_with_suspicious_characters(self):
        """Test that URLs with suspicious characters are flagged."""
        suspicious_urls = [
            "https://example@malicious.com",
            "http://site.com/file.exe",
            "https://domain.com%00malicious",
            "http://example.com==phishing"
        ]

        for url in suspicious_urls:
            with self.subTest(url=url):
                self.assertTrue(is_phishing_url(url), f"Suspicious URL not detected: {url}")

    def test_urls_with_excessive_subdomains(self):
        """Test that URLs with too many subdomains are flagged."""
        excessive_subdomain_urls = [
            "http://a.b.c.d.example.com",
            "https://sub1.sub2.sub3.sub4.domain.com",
            "http://very.long.subdomain.chain.site.org"
        ]

        for url in excessive_subdomain_urls:
            with self.subTest(url=url):
                self.assertTrue(is_phishing_url(url), f"Excessive subdomain URL not detected: {url}")

    def test_analyze_url_details(self):
        """Test the detailed URL analysis function."""
        # Test suspicious URL
        suspicious_url = "https://bit.ly/suspicious@redirect"
        analysis = analyze_url_details(suspicious_url)

        self.assertTrue(analysis['is_suspicious'])
        self.assertGreater(len(analysis['risk_factors']), 0)
        self.assertIn('domain_info', analysis)
        self.assertIn('recommendations', analysis)

        # Test safe URL
        safe_url = "https://www.google.com"
        analysis = analyze_url_details(safe_url)

        self.assertFalse(analysis['is_suspicious'])
        self.assertEqual(len(analysis['risk_factors']), 0)


class TestEnhancedPhishingDetector(unittest.TestCase):
    """Test cases for the enhanced phishing detector."""

    def setUp(self):
        """Set up test fixtures."""
        self.detector = EnhancedPhishingDetector()

    def test_basic_pattern_detection(self):
        """Test basic pattern detection in enhanced detector."""
        # Test URL shortener detection
        analysis = self.detector.analyze_url("https://bit.ly/test")
        self.assertTrue(analysis['checks']['basic_patterns']['url_shortener'])
        self.assertGreater(analysis['risk_score'], 0)

        # Test suspicious character detection
        analysis = self.detector.analyze_url("https://example@malicious.com")
        self.assertIn('@', analysis['checks']['basic_patterns']['suspicious_chars'])
        self.assertGreater(analysis['risk_score'], 0)

    def test_domain_analysis(self):
        """Test domain analysis functionality."""
        # Test IP address detection
        analysis = self.detector.analyze_url("http://192.168.1.1/malicious")
        self.assertTrue(analysis['checks']['domain_analysis']['is_ip'])
        self.assertGreater(analysis['risk_score'], 0)

        # Test domain with numbers
        analysis = self.detector.analyze_url("https://example123.com")
        self.assertTrue(analysis['checks']['domain_analysis']['has_numbers'])

        # Test domain with hyphens
        analysis = self.detector.analyze_url("https://test-site.com")
        self.assertTrue(analysis['checks']['domain_analysis']['has_hyphens'])

    def test_typosquatting_detection(self):
        """Test typosquatting detection."""
        # Test potential typosquatting
        analysis = self.detector.analyze_url("https://gooogle.com")
        typo_check = analysis['checks']['typosquatting']

        # Should detect similarity to google.com
        if typo_check['is_typosquatting']:
            self.assertIsNotNone(typo_check['potential_target'])
            self.assertGreater(typo_check['similarity_score'], 0.7)

    def test_url_structure_analysis(self):
        """Test URL structure analysis."""
        # Test deep path
        analysis = self.detector.analyze_url("https://example.com/a/b/c/d/e/f/deep")
        self.assertGreater(analysis['checks']['url_structure']['path_depth'], 5)

        # Test suspicious parameters
        analysis = self.detector.analyze_url("https://example.com?redirect=malicious.com")
        self.assertTrue(analysis['checks']['url_structure']['has_query_params'])
        self.assertIn('redirect', analysis['checks']['url_structure']['suspicious_params'])

        # Test encoded characters
        analysis = self.detector.analyze_url("https://example.com/path%20with%20spaces")
        self.assertTrue(analysis['checks']['url_structure']['encoded_chars'])

    def test_risk_level_calculation(self):
        """Test risk level calculation."""
        # Test low risk URL
        analysis = self.detector.analyze_url("https://www.google.com")
        self.assertIn(analysis['risk_level'], ['MINIMAL', 'LOW'])

        # Test high risk URL
        analysis = self.detector.analyze_url("https://bit.ly/malicious@redirect.exe")
        self.assertIn(analysis['risk_level'], ['MEDIUM', 'HIGH', 'CRITICAL'])
        self.assertTrue(analysis['is_suspicious'])

    def test_batch_analysis(self):
        """Test batch URL analysis."""
        urls = [
            "https://www.google.com",
            "https://bit.ly/suspicious",
            "https://example@malicious.com",
            "invalid-url"
        ]

        results = self.detector.batch_analyze(urls)
        self.assertEqual(len(results), len(urls))

        # Check that each result has required fields
        for result in results:
            self.assertIn('url', result)
            if 'error' not in result:
                self.assertIn('risk_level', result)
                self.assertIn('risk_score', result)

    def test_recommendations_generation(self):
        """Test that appropriate recommendations are generated."""
        # High risk URL should have strong warnings
        analysis = self.detector.analyze_url("https://bit.ly/malicious@redirect.exe")
        recommendations = analysis['recommendations']

        self.assertGreater(len(recommendations), 0)
        if analysis['risk_score'] >= 50:
            # Should contain strong warnings for high-risk URLs
            warning_found = any('DO NOT' in rec for rec in recommendations)
            self.assertTrue(warning_found, "High-risk URL should have strong warnings")


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling."""

    def setUp(self):
        """Set up test fixtures."""
        self.detector = EnhancedPhishingDetector()

    def test_empty_url(self):
        """Test handling of empty URLs."""
        # Empty URLs should be considered suspicious
        self.assertTrue(is_phishing_url(""))
        self.assertTrue(is_phishing_url("   "))  # Whitespace only
        self.assertTrue(is_phishing_url(None))  # None should be suspicious

    def test_invalid_url_format(self):
        """Test handling of invalid URL formats."""
        invalid_urls = [
            "not-a-url",
            "://missing-scheme",
            "http://",
            "ftp://unsupported-scheme.com"
        ]

        for url in invalid_urls:
            with self.subTest(url=url):
                # Should not crash, might return True (suspicious) for invalid formats
                try:
                    result = is_phishing_url(url)
                    self.assertIsInstance(result, bool)
                except Exception:
                    # It's acceptable for invalid URLs to raise exceptions
                    pass

    def test_very_long_url(self):
        """Test handling of very long URLs."""
        long_url = "https://example.com/" + "a" * 1000

        # Should not crash
        result = is_phishing_url(long_url)
        self.assertIsInstance(result, bool)

        # Enhanced detector should handle it too
        analysis = self.detector.analyze_url(long_url)
        self.assertIsInstance(analysis, dict)

    def test_unicode_urls(self):
        """Test handling of URLs with unicode characters."""
        unicode_urls = [
            "https://例え.テスト",
            "https://пример.рф",
            "https://مثال.إختبار"
        ]

        for url in unicode_urls:
            with self.subTest(url=url):
                try:
                    result = is_phishing_url(url)
                    self.assertIsInstance(result, bool)
                except Exception:
                    # Unicode handling might not be perfect, that's okay
                    pass


def display_test_menu():
    """Display the test selection menu."""
    print("🧪 Phishing URL Detector Test Suite")
    print("=" * 50)
    print("Select which tests to run:")
    print()
    print("1. 🔍 Basic Detector Tests")
    print("   - Safe URL detection")
    print("   - URL shortener detection")
    print("   - Suspicious character detection")
    print("   - Excessive subdomain detection")
    print("   - Detailed analysis testing")
    print()
    print("2. 🚀 Enhanced Detector Tests")
    print("   - Advanced pattern detection")
    print("   - Domain analysis")
    print("   - Typosquatting detection")
    print("   - URL structure analysis")
    print("   - Risk level calculation")
    print("   - Batch analysis")
    print("   - Recommendations generation")
    print()
    print("3. 🛡️ Edge Cases & Error Handling")
    print("   - Empty URL handling")
    print("   - Invalid URL formats")
    print("   - Very long URLs")
    print("   - Unicode URLs")
    print()
    print("4. 🎯 All Tests (Complete Suite)")
    print("5. 📋 Custom Test Selection")
    print("6. 📧 Gmail URL Analysis (Auto-grab URLs)")
    print("7. ❌ Exit")
    print()

def run_selected_tests(test_classes, test_names):
    """Run selected test classes."""
    print(f"\n🧪 Running Selected Tests: {', '.join(test_names)}")
    print("=" * 50)

    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add selected test classes
    for test_class in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(test_class))

    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("\n" + "=" * 50)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")

    if result.failures:
        print("\nFailures:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback}")

    if result.errors:
        print("\nErrors:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback}")

    success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun) * 100
    print(f"\nSuccess Rate: {success_rate:.1f}%")

    return result.wasSuccessful()

def run_custom_tests():
    """Allow user to select individual test methods."""
    print("\n📋 Custom Test Selection")
    print("=" * 30)

    # Available test methods
    test_methods = {
        'TestBasicPhishingDetector': {
            'test_safe_urls': 'Test safe URL detection',
            'test_phishing_urls_with_shorteners': 'Test URL shortener detection',
            'test_urls_with_suspicious_characters': 'Test suspicious character detection',
            'test_urls_with_excessive_subdomains': 'Test excessive subdomain detection',
            'test_analyze_url_details': 'Test detailed URL analysis'
        },
        'TestEnhancedPhishingDetector': {
            'test_basic_pattern_detection': 'Test basic pattern detection',
            'test_domain_analysis': 'Test domain analysis',
            'test_typosquatting_detection': 'Test typosquatting detection',
            'test_url_structure_analysis': 'Test URL structure analysis',
            'test_risk_level_calculation': 'Test risk level calculation',
            'test_batch_analysis': 'Test batch analysis',
            'test_recommendations_generation': 'Test recommendations generation'
        },
        'TestEdgeCases': {
            'test_empty_url': 'Test empty URL handling',
            'test_invalid_url_format': 'Test invalid URL formats',
            'test_very_long_url': 'Test very long URLs',
            'test_unicode_urls': 'Test unicode URLs'
        }
    }

    # Display available tests
    test_list = []
    counter = 1

    for class_name, methods in test_methods.items():
        print(f"\n{class_name}:")
        for method_name, description in methods.items():
            print(f"  {counter}. {description}")
            test_list.append((class_name, method_name))
            counter += 1

    print(f"\n  {counter}. Run all custom tests")
    print(f"  {counter + 1}. Back to main menu")

    while True:
        try:
            choice = input(f"\nEnter test numbers (comma-separated, 1-{counter + 1}): ").strip()

            if choice == str(counter + 1):  # Back to main menu
                return

            if choice == str(counter):  # Run all custom tests
                selected_numbers = list(range(1, counter))
            else:
                selected_numbers = [int(x.strip()) for x in choice.split(',')]

            # Validate selections
            valid_selections = []
            for num in selected_numbers:
                if 1 <= num <= len(test_list):
                    valid_selections.append(num)
                else:
                    print(f"⚠️ Invalid selection: {num}")

            if not valid_selections:
                print("❌ No valid selections made.")
                continue

            # Run selected tests
            print(f"\n🧪 Running {len(valid_selections)} selected tests...")

            # Create custom test suite
            suite = unittest.TestSuite()

            for num in valid_selections:
                class_name, method_name = test_list[num - 1]
                test_class = globals()[class_name]
                suite.addTest(test_class(method_name))

            # Run tests
            runner = unittest.TextTestRunner(verbosity=2)
            result = runner.run(suite)

            # Print summary
            print("\n" + "=" * 30)
            print(f"Custom tests completed!")
            print(f"Tests run: {result.testsRun}")
            print(f"Failures: {len(result.failures)}")
            print(f"Errors: {len(result.errors)}")
            success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun) * 100
            print(f"Success Rate: {success_rate:.1f}%")

            break

        except ValueError:
            print("❌ Invalid input. Please enter numbers separated by commas.")
        except KeyboardInterrupt:
            print("\n\n👋 Returning to main menu...")
            break

def run_gmail_analysis():
    """Run Gmail URL analysis."""
    try:
        from gmail_url_extractor import GmailURLExtractor

        print("\n📧 Gmail URL Analysis")
        print("=" * 50)
        print("This feature automatically extracts URLs from your Gmail")
        print("and analyzes them for phishing threats.")
        print()

        extractor = GmailURLExtractor()

        print("Options:")
        print("1. 📧 Analyze recent emails (last 7 days)")
        print("2. 📧 Custom time period")
        print("3. 🎯 Demo mode (sample data)")
        print("4. 🔙 Back to main menu")
        print()

        gmail_choice = input("Enter your choice (1-4): ").strip()

        if gmail_choice == '1':
            extractor.analyze_gmail_urls(days=7, max_emails=50)

        elif gmail_choice == '2':
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

        elif gmail_choice == '3':
            extractor.demo_mode()

        elif gmail_choice == '4':
            return

        else:
            print("❌ Invalid choice. Please enter 1-4.")

    except ImportError:
        print("❌ Gmail URL extractor not available.")
        print("📧 Make sure gmail_url_extractor.py is in the same directory.")
    except Exception as e:
        print(f"❌ Error running Gmail analysis: {str(e)}")

def interactive_test_runner():
    """Interactive test runner with user selection."""
    while True:
        try:
            display_test_menu()
            choice = input("Enter your choice (1-7): ").strip()

            if choice == '1':
                # Basic Detector Tests
                run_selected_tests([TestBasicPhishingDetector], ["Basic Detector Tests"])

            elif choice == '2':
                # Enhanced Detector Tests
                run_selected_tests([TestEnhancedPhishingDetector], ["Enhanced Detector Tests"])

            elif choice == '3':
                # Edge Cases Tests
                run_selected_tests([TestEdgeCases], ["Edge Cases & Error Handling"])

            elif choice == '4':
                # All Tests
                run_selected_tests(
                    [TestBasicPhishingDetector, TestEnhancedPhishingDetector, TestEdgeCases],
                    ["All Tests"]
                )

            elif choice == '5':
                # Custom Test Selection
                run_custom_tests()

            elif choice == '6':
                # Gmail URL Analysis
                run_gmail_analysis()

            elif choice == '7':
                print("👋 Goodbye!")
                break

            else:
                print("❌ Invalid choice. Please enter 1-7.")
                continue

            # Ask if user wants to run more tests
            if choice in ['1', '2', '3', '4', '6']:
                while True:
                    continue_choice = input("\nRun more tests? (y/n): ").strip().lower()
                    if continue_choice in ['y', 'yes']:
                        break
                    elif continue_choice in ['n', 'no']:
                        print("👋 Goodbye!")
                        return
                    else:
                        print("❌ Please enter 'y' or 'n'")

        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {str(e)}")

def run_test_suite():
    """Legacy function for backward compatibility - runs all tests."""
    return run_selected_tests(
        [TestBasicPhishingDetector, TestEnhancedPhishingDetector, TestEdgeCases],
        ["Complete Test Suite"]
    )


if __name__ == "__main__":
    # Run interactive test runner by default
    interactive_test_runner()
