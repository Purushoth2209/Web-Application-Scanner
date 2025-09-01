import json
import time
import requests
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import TimeoutException, ElementNotInteractableException, StaleElementReferenceException
from html import unescape


# Load XSS payloads from JSON file
with open("xss_payloads.json", "r") as f:
    xss_payloads_dict = json.load(f)

xss_payloads = []
for category, payloads in xss_payloads_dict.items():
    xss_payloads.extend(payloads)


def get_driver(preferred="firefox", headless=True):
    print(f"[*] Initializing browser driver: {preferred} (headless={headless})")
    driver = None
    if preferred == "firefox":
        try:
            options = FirefoxOptions()
            if headless:
                options.add_argument("--headless")
            driver = webdriver.Firefox(service=FirefoxService(), options=options)
            print("[+] Firefox driver initialized successfully")
            return driver
        except Exception as e:
            print(f"[-] Firefox failed: {e}")
            print("[*] Falling back to Chrome...")

    if preferred == "chrome":
        try:
            options = ChromeOptions()
            if headless:
                options.add_argument("--headless")
            driver = webdriver.Chrome(service=ChromeService(), options=options)
            print("[+] Chrome driver initialized successfully")
            return driver
        except Exception as e:
            print(f"[-] Chrome failed: {e}")
            print("[!] No working browser found. Install geckodriver or chromedriver.")
            raise

    return driver

def dismiss_cookie_banner(driver):
    """
    Attempts to dismiss common cookie consent banners.
    """
    print("[*] Checking for cookie consent banner...")
    try:
        # Common selectors for "Accept", "Got it!", "Dismiss" buttons
        cookie_button_selectors = [
            (By.XPATH, "//button[contains(normalize-space(), 'Got it!')]"),
            (By.XPATH, "//a[contains(normalize-space(), 'Got it!')]"),
            (By.XPATH, "//button[contains(normalize-space(), 'Accept')]"),
            (By.XPATH, "//a[contains(normalize-space(), 'Accept')]"),
            (By.XPATH, "//button[contains(normalize-space(), 'Dismiss')]"),
            (By.XPATH, "//a[contains(normalize-space(), 'Dismiss')]"),
            (By.ID, "cookieconsent:button"), # Specific for some cookie consent libs
            (By.CSS_SELECTOR, ".cc-window .cc-btn.cc-allow"), # Generic for cookieconsent.js
            (By.CSS_SELECTOR, ".cc-btn.cc-dismiss"), # Another common one
            (By.CSS_SELECTOR, "[aria-label='Accept cookies']"), # Accessibility friendly
        ]

        for by_type, selector in cookie_button_selectors:
            try:
                cookie_button = WebDriverWait(driver, 3).until(
                    EC.element_to_be_clickable((by_type, selector))
                )
                if cookie_button:
                    # Use JavaScript click to bypass potential interception by other elements
                    driver.execute_script("arguments[0].click();", cookie_button)
                    print("[+] Cookie consent banner dismissed.")
                    time.sleep(1) # Give it a moment to disappear
                    return True # Banner dismissed
            except TimeoutException:
                continue # Try next selector
            except StaleElementReferenceException:
                # Element became stale, try again (e.g., if page reloaded slightly)
                time.sleep(0.5)
                continue
            except Exception as e:
                print(f"[-] Error trying to click cookie button '{selector}': {e}")
                continue # Try next selector
        print("[-] No cookie consent banner found or dismissed within timeout.")
        return False
    except Exception as e:
        print(f"[-] General error during cookie banner dismissal: {e}")
        return False


def fetch_forms_and_inputs_selenium(url, driver): # Modified to accept existing driver
    print(f"[*] Navigating to {url} to fetch forms and inputs")
    driver.get(url)
    dismiss_cookie_banner(driver) # Dismiss banner after navigating

    # Wait until at least one input is visible (handles JS-heavy SPAs)
    try:
        WebDriverWait(driver, 8).until(
            EC.presence_of_element_located((By.TAG_NAME, "input"))
        )
        print("[+] At least one input detected on page")
    except TimeoutException:
        print("[-] No input visible immediately, continuing anyway...")

    forms_data = []
    forms = driver.find_elements(By.TAG_NAME, "form")
    print(f"[*] Found {len(forms)} <form> elements on page")

    # --- Collect forms normally ---
    for idx, form in enumerate(forms, start=1):
        form_action = form.get_attribute("action") or url
        form_method = form.get_attribute("method") or "get"
        print(f"    [+] Form #{idx}: action={form_action}, method={form_method}")

        inputs_info = {} # Store info to re-locate later
        input_elements = form.find_elements(By.TAG_NAME, "input")
        textarea_elements = form.find_elements(By.TAG_NAME, "textarea")

        for elem in input_elements + textarea_elements:
            name = elem.get_attribute("name") or elem.get_attribute("id")
            if name:
                inputs_info[name] = {
                    "tag": elem.tag_name,
                    "id": elem.get_attribute("id"),
                    "name": elem.get_attribute("name"),
                    "type": elem.get_attribute("type") # Store type for later
                }
                print(f"        - Found input field: {name} (type={inputs_info[name]['type']})")

        forms_data.append({
            "action": form_action,
            "method": form_method.lower(),
            "inputs_info": inputs_info, # Store info, not stale elements
            "form_element_id": form.get_attribute("id") if form.get_attribute("id") else None # Store ID to re-locate form
        })

    # --- Handle standalone inputs (not inside any form) ---
    standalone_elements = driver.find_elements(
        By.XPATH, "//input[not(ancestor::form)] | //textarea[not(ancestor::form)]"
    )
    if standalone_elements:
        print(f"[*] Found {len(standalone_elements)} standalone input(s)/textarea(s) (outside <form>)")
        inputs_info = {}
        for elem in standalone_elements:
            name = elem.get_attribute("name") or elem.get_attribute("id")
            if name:
                inputs_info[name] = {
                    "tag": elem.tag_name,
                    "id": elem.get_attribute("id"),
                    "name": elem.get_attribute("name"),
                    "type": elem.get_attribute("type")
                }
                print(f"        - Found standalone input: {name} (type={inputs_info[name]['type']})")

        if inputs_info:
            forms_data.append({
                "action": url,
                "method": "get",
                "inputs_info": inputs_info,
                "form_element_id": None # No form element for standalone
            })

    return forms_data # Return only forms_data, as driver is managed externally


def is_payload_reflected(payload, response_text):
    resp_body = unescape(response_text)
    reflected = payload in resp_body or payload.lower() in resp_body.lower()
    print(f"        [~] Checking reflection for payload: {payload[:30]}... -> {'YES' if reflected else 'NO'}")
    return reflected


def test_xss_on_form_requests(form_data, payload):
    """Fallback server-side reflection test. Skips Angular hash-routes."""
    action_url = form_data["action"]

    if "#/" in action_url:
        print(f"        [~] Skipping request test for SPA route: {action_url}")
        return False

    method = form_data["method"]
    # For server-side, we just need names, not element objects
    inputs = {name: payload for name in form_data["inputs_info"]}
    print(f"    [>] Sending {method.upper()} request to {action_url} with payload: {payload[:30]}...")

    try:
        if method == "post":
            response = requests.post(action_url, data=inputs, timeout=5)
        else:
            response = requests.get(action_url, params=inputs, timeout=5)
        response.raise_for_status()

        if is_payload_reflected(payload, response.text):
            return True
    except requests.exceptions.RequestException as e:
        print(f"    [!] Request failed: {e}")
    return False


def test_xss_with_selenium(driver, form_data, payload):
    print(f"    [>] Testing with Selenium payload injection: {payload[:40]}...")

    interacted_inputs = []

    for name, input_info in form_data["inputs_info"].items():
        try:
            # Re-locate the element since the page might have reloaded or elements refreshed
            current_element = None
            if input_info["id"]:
                current_element = WebDriverWait(driver, 3).until(
                    EC.presence_of_element_located((By.ID, input_info["id"]))
                )
            elif input_info["name"]:
                 current_element = WebDriverWait(driver, 3).until(
                    EC.presence_of_element_located((By.NAME, input_info["name"]))
                )
            elif input_info["tag"] == "textarea": # Textarea without id/name might be found by tag
                 current_element = WebDriverWait(driver, 3).until(
                    EC.presence_of_element_located((By.TAG_NAME, "textarea"))
                )
            # Add more robust selection if needed, e.g., by class

            if not current_element:
                print(f"        [!] Could not re-locate input element: {name}")
                continue

            input_type = input_info["type"] # Use stored type or re-fetch
            if not input_type:
                 input_type = current_element.get_attribute("type") or "text"


            if input_type in ["hidden", "submit", "button", "file"]:
                print(f"        [~] Skipping input: {name} (type={input_type})")
                continue

            # Handle checkbox explicitly
            if input_type == "checkbox":
                if not current_element.is_selected(): # Only click if not already selected
                    # Use JavaScript click to ensure it's interactable
                    driver.execute_script("arguments[0].click();", current_element)
                print(f"        - Toggled checkbox: {name}")
                interacted_inputs.append(current_element)
                continue

            # Skip specific non-interactable inputs if known (like mat-input-1 for Juice Shop)
            if name == "mat-input-1":
                 print(f"        [~] Skipping known non-interactable input: {name}")
                 continue

            current_element.clear()
            current_element.send_keys(payload)
            print(f"        - Injected payload into: {name}")
            interacted_inputs.append(current_element)

        except ElementNotInteractableException:
            print(f"        [!] Could not interact with input: {name}")
        except StaleElementReferenceException:
            print(f"        [!] Stale element reference for input: {name}. Page likely refreshed unexpectedly.")
        except TimeoutException:
            print(f"        [!] Timeout re-locating input element: {name}")
        except Exception as e:
            print(f"        [!] Unexpected error on input {name}: {e}")

    # Try to submit the form/inputs
    submitted = False

    # 1. Try explicit form submission if a form element exists and can be re-located
    if form_data["form_element_id"]:
        try:
            form_element = WebDriverWait(driver, 3).until(
                EC.presence_of_element_located((By.ID, form_data["form_element_id"]))
            )
            form_element.submit()
            print("        [>] Submitted form via .submit()")
            submitted = True
        except TimeoutException:
            print("        [!] Form element not found or stale for .submit()")
        except Exception as e:
            print(f"        [!] Form .submit() failed: {e}")

    # 2. Try to find and click a more specific login/submit button (especially for SPAs)
    if not submitted and interacted_inputs:
        try:
            # Common selectors for login/submit buttons (Juice Shop's loginButton)
            submit_button = WebDriverWait(driver, 5).until( # Increased timeout for button
                EC.element_to_be_clickable((By.CSS_SELECTOR,
                                            "button[type='submit'], button[id='loginButton'], button[aria-label*='Login'], button.btn-primary"))
            )
            # Use JavaScript click to bypass potential interception
            driver.execute_script("arguments[0].click();", submit_button)
            print("        [>] Submitted via specific submit/login button click (JS click)")
            submitted = True
        except TimeoutException:
            print("        [!] No specific submit/login button found or clickable within timeout.")
        except Exception as e:
            print(f"        [!] Error clicking specific submit/login button: {e}")

    # 3. Fallback: Send RETURN key to the last interacted input field
    if not submitted and interacted_inputs:
        try:
            # Ensure the last interacted input is still valid or re-locate it
            last_input = interacted_inputs[-1]
            try:
                # Check if it's still attached to the DOM
                last_input.is_displayed()
            except StaleElementReferenceException:
                # If stale, try to re-locate it using its info
                last_input_info = form_data["inputs_info"][last_input.get_attribute("name") or last_input.get_attribute("id")]
                if last_input_info["id"]:
                    last_input = WebDriverWait(driver, 3).until(EC.presence_of_element_located((By.ID, last_input_info["id"])))
                elif last_input_info["name"]:
                    last_input = WebDriverWait(driver, 3).until(EC.presence_of_element_located((By.NAME, last_input_info["name"])))
                else:
                    raise Exception("Cannot re-locate last input for RETURN key.")

            last_input.send_keys(Keys.RETURN)
            print("        [>] Submitted with RETURN key on an input field")
            submitted = True
        except Exception as e:
            print(f"        [!] Failed to submit with RETURN key: {e}")

    if not submitted:
        print("        [!] Could not find a way to submit the payload.")


    # Check for JS alert popup
    try:
        WebDriverWait(driver, 5).until(EC.alert_is_present()) # Increased timeout to 5s
        alert = driver.switch_to.alert
        alert.dismiss()
        print("        [+] DOM XSS triggered (alert detected!)")
        return True
    except TimeoutException:
        print("        [-] No alert triggered for this payload")
        return False


def scan_xss(target_url, browser_choice="firefox"):
    print(f"[*] Starting XSS scan on: {target_url}")
    vulnerabilities = []
    driver = None # Initialize driver to None

    try:
        driver = get_driver(browser_choice) # Get the driver once

        # Initial fetch of forms and inputs
        forms_on_page = fetch_forms_and_inputs_selenium(target_url, driver)

        if not forms_on_page:
            print(f"[-] No forms or inputs found on {target_url}.")
            return vulnerabilities

        print(f"[*] Found {len(forms_on_page)} form/input group(s). Beginning payload injection...")
        for form in forms_on_page:
            print(f"\n    [*] Testing target at {form['action']} ({form['method'].upper()})")
            for payload in xss_payloads:
                # Navigate back to the target URL before each payload injection
                # This ensures a clean state for each test run.
                driver.get(target_url)
                dismiss_cookie_banner(driver) # Dismiss banner on each page load
                time.sleep(1) # Give it a moment to load and settle

                if test_xss_with_selenium(driver, form, payload):
                    vulnerabilities.append({
                        "type": "DOM XSS (Injection)",
                        "url": target_url,
                        "payload": payload
                    })
                # Only run server-side check if DOM XSS not found and it's not an SPA route
                elif "#/" not in form['action'] and test_xss_on_form_requests(form, payload):
                    vulnerabilities.append({
                        "type": "Reflected XSS (Injection)",
                        "url": form["action"],
                        "method": form["method"],
                        "payload": payload
                    })

    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user. Shutting down browser...")
    except Exception as e:
        print(f"\n[!] An unexpected error occurred during the scan: {e}")
    finally:
        if driver:
            driver.quit() # Ensure driver is always closed
    return vulnerabilities


if __name__ == "__main__":
    target = input("Enter target URL: ").strip()
    browser_choice = input("Choose browser (firefox/chrome) [default: firefox]: ").strip().lower() or "firefox"
    results = scan_xss(target, browser_choice)

    print("\n--- XSS Scan Results ---")
    if results:
        for vul in results:
            print(f"Vulnerability Type: {vul['type']}")
            print(f"Affected URL: {vul['url']}")
            if "method" in vul:
                print(f"Method: {vul['method']}")
            print(f"Payload Used: {vul['payload']}\n")

        with open("xss_results.json", "w") as f:
            json.dump(results, f, indent=2)
        print("[*] Results saved to xss_results.json")
    else:
        print("No XSS vulnerabilities detected.")