# SQL Injection Tester

SQL Injection Tester - Development Process and Version History
Overview
This project, SQL Injection Tester, was developed entirely with the assistance of ChatGPT, an AI-powered coding assistant. The tool was designed to automate the process of testing login forms for SQL Injection (SQLi) vulnerabilities using a variety of payloads.

The development process followed an iterative approach, refining the script across multiple versions to improve functionality, performance, and usability. Each version introduced enhancements such as multi-threading, better logging, more SQLi payloads, and GitHub integration.

Development Process & Versions
Version 1.0 - Basic SQL Injection Tester
Initial Concept & Implementation

ChatGPT generated a simple script that sent SQL injection payloads to a login form.
Hardcoded SQLi payloads were used.
Requests were sent sequentially, making the process slower.
Basic response length comparison was implemented.
💡 Key Features:
✅ Basic SQL Injection payloads
✅ Response length-based detection
✅ Command-line arguments for target URL

💻 Code was tested in PowerShell to ensure functionality before refining further.

Version 2.0 - Enhanced Payloads & Logging
Improvements Based on Initial Testing

Expanded SQL Injection payloads, including authentication bypass, UNION-based, error-based, and time-based injections.
Introduced response elapsed time tracking to detect time-based SQLi.
Added structured logging using Python's logging module.
💡 Key Features:
✅ More comprehensive SQLi payload list
✅ Time-based attack detection
✅ Improved error handling

Version 3.0 - Multi-threading & Heuristic-Based Detection
Optimizing Execution Speed

ChatGPT added multi-threading to execute multiple payloads in parallel, significantly reducing execution time.
Introduced heuristic-based detection, which considers both response length differences and timing delays to identify vulnerabilities more accurately.
Implemented support for # as a comment marker, in addition to --.
💡 Key Features:
✅ Multi-threading for faster execution
✅ Heuristic-based SQL Injection detection
✅ Support for both # and -- as SQL comment markers

Version 4.0 - GitHub Integration & README Documentation
Finalizing and Uploading the Project

GitHub repository was created, and all files were uploaded.
ChatGPT generated a detailed README.md file, including installation instructions, usage examples, and licensing information.
Debugged minor issues related to GitHub remote URL configuration.
💡 Key Features:
✅ Repository uploaded to GitHub
✅ README.md added for better documentation
✅ Enhanced command-line arguments for customization

Project Contributions
🔹 All code was generated and iteratively improved by ChatGPT, based on user feedback.
🔹 User provided real-world testing scenarios, allowing refinements to payload effectiveness and detection accuracy.
🔹 Final optimizations focused on performance, usability, and ethical considerations (ensuring the tool is only used for security testing on authorized systems).

