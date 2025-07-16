# 🚀 Quick Start Guide - How to Run the Program

## 📋 **3 Simple Commands to Run the Program**

### **1. 🔍 Basic Detector (RECOMMENDED FOR BEGINNERS)**
```bash
python phishing_detector.py
```
**What it does:**
- Interactive URL checker
- Enter URLs to analyze (e.g., `google.com`, `bit.ly/test`)
- Get instant phishing detection results
- Type `quit` to exit

**Example:**
```
Enter a URL to check: google.com
✅ Looks safe (based on simple rules).

Enter a URL to check: bit.ly/test
⚠️ WARNING: This might be a phishing URL!
```

### **2. 🚀 Enhanced Detector (ADVANCED FEATURES)**
```bash
python enhanced_detector.py
```
**What it does:**
- Advanced risk scoring (0-100 scale)
- Detailed analysis with risk levels
- Batch processing for multiple URLs
- Type `help` for commands, `quit` to exit

**Example:**
```
Enter command or URL: bit.ly/test
Risk Level: MEDIUM (Score: 35/100)
⚠️ SUSPICIOUS URL DETECTED
```

### **3. 🧪 Test Selection (VERIFY PROGRAM WORKS)**
```bash
python test_detector.py
```
**What it does:**
- Interactive test menu
- Choose which tests to run
- Verify program functionality
- Select from 6 options

**Example:**
```
Select which tests to run:
1. Basic Detector Tests (5 tests)
2. Enhanced Detector Tests (7 tests)
3. All Tests (16 tests)
Enter your choice (1-6): 1
```

## 🎯 **Which Command Should You Use?**

### **👶 New User? Start Here:**
```bash
python phishing_detector.py
```
- Simple and easy to use
- Perfect for learning how it works
- Enter URLs and see results immediately

### **🔧 Want Advanced Features?**
```bash
python enhanced_detector.py
```
- Risk scoring and detailed analysis
- Batch processing for multiple URLs
- Professional-grade detection

### **🧪 Want to Test the Program?**
```bash
python test_detector.py
```
- Verify everything works correctly
- Choose specific tests to run
- See detailed test results

## 📝 **Step-by-Step Instructions**

### **Step 1: Open Terminal/Command Prompt**
- **Windows:** Press `Win + R`, type `cmd`, press Enter
- **Mac:** Press `Cmd + Space`, type `terminal`, press Enter
- **Linux:** Press `Ctrl + Alt + T`

### **Step 2: Navigate to Program Folder**
```bash
cd "path/to/your/program/folder"
```

### **Step 3: Run the Program**
```bash
python phishing_detector.py
```

### **Step 4: Use the Program**
- Type URLs to check (e.g., `google.com`, `bit.ly/test`)
- Read the results
- Type `quit` when done

## 🔍 **Example URLs to Test**

### **Safe URLs:**
- `google.com`
- `github.com`
- `stackoverflow.com`
- `microsoft.com`

### **Suspicious URLs:**
- `bit.ly/test` (URL shortener)
- `example@malicious.com` (@ symbol)
- `site.com/file.exe` (suspicious file)
- `192.168.1.1` (IP address)

## ⚠️ **Troubleshooting**

### **"python is not recognized"**
**Solution:** Try these alternatives:
```bash
python3 phishing_detector.py
py phishing_detector.py
```

### **"No such file or directory"**
**Solution:** Make sure you're in the correct folder:
```bash
ls                    # Linux/Mac: List files
dir                   # Windows: List files
cd path/to/program    # Navigate to program folder
```

### **Program seems stuck**
**Solution:** Press `Ctrl + C` to stop and restart

## 💡 **Tips for Success**

1. **Start Simple:** Use `python phishing_detector.py` first
2. **Test URLs:** Try both safe and suspicious URLs
3. **Read Results:** Pay attention to warnings and recommendations
4. **Exit Properly:** Type `quit` to exit cleanly
5. **Run Tests:** Use `python test_detector.py` to verify everything works

## 🎯 **Quick Reference**

| Command | Purpose | Best For |
|---------|---------|----------|
| `python phishing_detector.py` | Basic URL checking | Beginners |
| `python enhanced_detector.py` | Advanced analysis | Power users |
| `python test_detector.py` | Test the program | Verification |

## 🚀 **Ready to Start?**

**Run this command to begin:**
```bash
python phishing_detector.py
```

**Then type a URL like:** `google.com` or `bit.ly/test`

**Your Phishing URL Detector is ready to protect you!** 🛡️
