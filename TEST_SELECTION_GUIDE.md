# 🧪 Test Selection Guide - User Chooses Tests

## ✅ **CONFIRMED: Users Can Select the Tests They Need!**

The Phishing URL Detector now includes an interactive test selection system that allows users to choose exactly which tests to run.

## 🎯 **How to Use Test Selection**

### **Start the Test System:**
```bash
python test_detector.py
```

### **Interactive Menu:**
```
🧪 Phishing URL Detector Test Suite
==================================================
Select which tests to run:

1. 🔍 Basic Detector Tests
   - Safe URL detection
   - URL shortener detection
   - Suspicious character detection
   - Excessive subdomain detection
   - Detailed analysis testing

2. 🚀 Enhanced Detector Tests
   - Advanced pattern detection
   - Domain analysis
   - Typosquatting detection
   - URL structure analysis
   - Risk level calculation
   - Batch analysis
   - Recommendations generation

3. 🛡️ Edge Cases & Error Handling
   - Empty URL handling
   - Invalid URL formats
   - Very long URLs
   - Unicode URLs

4. 🎯 All Tests (Complete Suite)
5. 📋 Custom Test Selection
6. ❌ Exit

Enter your choice (1-6):
```

## 📋 **Test Selection Options**

### **Option 1: Basic Detector Tests (5 tests)**
- Tests core phishing detection functionality
- Validates URL shortener detection
- Checks suspicious character recognition
- Verifies subdomain analysis
- **Use when:** Testing basic functionality

### **Option 2: Enhanced Detector Tests (7 tests)**
- Tests advanced risk scoring
- Validates domain analysis
- Checks typosquatting detection
- Verifies URL structure analysis
- Tests batch processing
- **Use when:** Testing advanced features

### **Option 3: Edge Cases Tests (4 tests)**
- Tests error handling
- Validates input validation
- Checks unicode support
- Verifies long URL handling
- **Use when:** Testing robustness

### **Option 4: All Tests (16 tests)**
- Runs complete test suite
- Comprehensive validation
- **Use when:** Full system verification

### **Option 5: Custom Test Selection**
- Pick individual tests from a list
- Mix and match specific tests
- **Use when:** Testing specific functionality

### **Option 6: Exit**
- Quit the test system

## 🎯 **Custom Test Selection Example**

When you choose option 5, you get:

```
📋 Custom Test Selection
==============================
Available individual tests:

TestBasicPhishingDetector:
  1. Test safe URL detection
  2. Test URL shortener detection
  3. Test suspicious character detection
  4. Test excessive subdomain detection
  5. Test detailed URL analysis

TestEnhancedPhishingDetector:
  6. Test basic pattern detection
  7. Test domain analysis
  8. Test typosquatting detection
  9. Test URL structure analysis
  10. Test risk level calculation
  11. Test batch analysis
  12. Test recommendations generation

TestEdgeCases:
  13. Test empty URL handling
  14. Test invalid URL formats
  15. Test very long URLs
  16. Test unicode URLs

  17. Run all custom tests
  18. Back to main menu

Enter test numbers (comma-separated, 1-18): 1,2,3
```

**Example inputs:**
- `1,2,3` - Run tests 1, 2, and 3
- `6,7,8,9` - Run enhanced detector tests
- `13,14,15,16` - Run edge case tests
- `17` - Run all individual tests

## 📊 **Test Results Example**

```
🧪 Running Selected Tests: Basic Detector Tests
==================================================

test_safe_urls ... ok
test_phishing_urls_with_shorteners ... ok
test_urls_with_suspicious_characters ... ok
test_urls_with_excessive_subdomains ... ok
test_analyze_url_details ... ok

----------------------------------------------------------------------
Ran 5 tests in 0.025s

OK

==================================================
Tests run: 5
Failures: 0
Errors: 0
Success Rate: 100.0%

Run more tests? (y/n): n
👋 Goodbye!
```

## ✅ **Key Features**

### **User Control:**
- ✅ Users choose which tests to run
- ✅ No forced execution of all tests
- ✅ Flexible test selection
- ✅ Clear test descriptions

### **Interactive Interface:**
- ✅ Clear menu with options
- ✅ Descriptive test categories
- ✅ User-friendly prompts
- ✅ Option to run more tests

### **Test Organization:**
- ✅ Logical test groupings
- ✅ Individual test selection
- ✅ Complete suite option
- ✅ Easy navigation

### **Results Display:**
- ✅ Clear test output
- ✅ Success/failure reporting
- ✅ Detailed summaries
- ✅ Professional formatting

## 🚀 **Usage Scenarios**

### **Developer Testing:**
```bash
# Test basic functionality during development
python test_detector.py
Choice: 1 (Basic Detector Tests)
```

### **Feature Validation:**
```bash
# Test specific new features
python test_detector.py
Choice: 5 (Custom Selection)
Input: 7,8,9 (Domain analysis features)
```

### **Quality Assurance:**
```bash
# Run complete test suite
python test_detector.py
Choice: 4 (All Tests)
```

### **Bug Investigation:**
```bash
# Test edge cases for debugging
python test_detector.py
Choice: 3 (Edge Cases)
```

## 🎯 **Benefits**

1. **Time Efficient** - Run only needed tests
2. **Focused Testing** - Target specific functionality
3. **User Friendly** - Clear options and descriptions
4. **Flexible** - Multiple selection methods
5. **Professional** - Clean interface and reporting

---

## 🎉 **Summary**

**The test selection system ensures users have complete control over which tests to run!**

- ✅ **6 Selection Options** - From basic to custom
- ✅ **16 Individual Tests** - All can be selected independently  
- ✅ **Interactive Interface** - User-friendly menus
- ✅ **Flexible Execution** - Run exactly what you need
- ✅ **Professional Results** - Clear reporting and summaries

**Users can now select the exact tests they need for their specific requirements!** 🧪
