# SQL Injection Tester — Lightweight Web App Vulnerability Scanner

**SQL Injection Tester** is a lightweight Python tool designed to automate the testing of login forms for common SQL Injection (SQLi) vulnerabilities.  
Built for efficient testing in home labs, CTF challenges, and authorized penetration tests, this tool emphasizes speed, modularity, and real-world attack simulation.

---

## 📚 Features

- Tests login forms using a curated list of SQL Injection payloads
- Detects:
  - Authentication bypass
  - UNION-based injections
  - Error-based injections
  - Time-based (delayed response) injections
- Multi-threaded execution for faster payload delivery
- Heuristic detection combining response size and response time
- Command-line customization for target URLs, timeout values, and thread counts
- Secure error handling and structured logging for analysis

---

## 📌 About This Project

The initial development of this tool was supported through AI-assisted ideation (ChatGPT) to optimize SQL payload testing and detection logic.  
Final implementation, testing, and optimization were performed manually using real-world scenarios in a controlled home lab environment.

---

## 🤖 AI Assistance Disclosure

This project was developed by leveraging AI (ChatGPT) for ideation and optimization assistance, combined with manual testing, real-world scenario development, and hands-on coding refinement.

---

## 📫 Contact

- Nick Robb | Cybersecurity Professional
- Email: Nick.T.Robb@gmail.com
- LinkedIn: [Nick Robb](https://www.linkedin.com/in/nickrobb/)

---

## ⚙️ Requirements

- Python 3.8+
- `requests` Python library

Install dependencies:

```bash
pip install requests

