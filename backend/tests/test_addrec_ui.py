from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
from datetime import date

# --- CONFIG ---
URL = "http://localhost:5000/doctor/addRecord/1"
CHROME_PATH = "/usr/bin/chromium-browser"  # adjust for local env

# --- SETUP ---
options = Options()
options.add_argument("--headless")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")
options.binary_location = CHROME_PATH
driver = webdriver.Chrome(options=options)

try:
    driver.get(URL)
    wait = WebDriverWait(driver, 10)

    # Wait for form to load
    wait.until(EC.presence_of_element_located((By.ID, "diagnosis")))

    # Fill the form
    driver.find_element(By.ID, "diagnosis").send_keys("UI test: patient is doing well.")
    driver.find_element(By.ID, "date").send_keys(date.today().isoformat())

    # Ensure patient_id hidden field exists
    patient_id_elem = driver.find_element(By.NAME, "patient_id")
    assert patient_id_elem.get_attribute("value") == "1"

    # Submit the form
    submit_button = driver.find_element(By.XPATH, '//button[@type="submit"]')
    driver.execute_script("arguments[0].scrollIntoView(true);", submit_button)
    time.sleep(0.5)
    submit_button.click()

    time.sleep(2)
    driver.save_screenshot("add_record_result.png")

    # Check for expected result
    if "records" in driver.current_url.lower():
        print("✅ Add Record test passed: Redirected to records page.")
    else:
        print("⚠️ Add Record did not redirect. Check for flash messages or validation errors.")
        errors = driver.find_elements(By.CLASS_NAME, "text-danger")
        for err in errors:
            print(" -", err.text)

except Exception as e:
    driver.save_screenshot("add_record_error.png")
    print("❌ Exception during test:", e)

finally:
    driver.quit()
