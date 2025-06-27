from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
from datetime import date

# --- CONFIG ---
LOGIN_URL = "http://localhost:5000/test-login-doctor"
ADD_RECORD_URL = "http://localhost:5000/doctor/addRecord/1"
EXPECTED_REDIRECT = "http://localhost:5000/doctor/patientRecords/1"
CHROME_PATH = "/usr/bin/chromium-browser"  

# --- SETUP ---
options = Options()
options.add_argument("--headless")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")
options.binary_location = CHROME_PATH
driver = webdriver.Chrome(options=options)

try:
    wait = WebDriverWait(driver, 10)

    # ✅ 1. Login via test route
    driver.get(LOGIN_URL)
    wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))
    print("✅ Logged in via test-login-doctor")

    # ✅ 2. Go to Add Record page
    driver.get(ADD_RECORD_URL)
    wait.until(EC.presence_of_element_located((By.ID, "diagnosis")))

    # ✅ 3. Fill and submit the form
    driver.find_element(By.ID, "diagnosis").send_keys("UI test: patient is doing well.")
    driver.find_element(By.ID, "date").send_keys(date.today().isoformat())

    patient_id_elem = driver.find_element(By.NAME, "patient_id")
    assert patient_id_elem.get_attribute("value") == "1"

    submit_button = driver.find_element(By.XPATH, '//button[@type="submit"]')
    driver.execute_script("arguments[0].scrollIntoView(true);", submit_button)
    time.sleep(0.5)
    submit_button.click()

    # ✅ 4. Wait for redirect
    try:
        wait.until(EC.url_changes(ADD_RECORD_URL))
    except:
        print("⚠️ URL did not change after form submit — possible form error.")
    
    # ✅ 5. Check final URL
    final_url = driver.current_url
    print("🔗 Final URL:", final_url)
    
    if final_url == EXPECTED_REDIRECT:
        print("✅ Add Record test passed: Redirected to expected patient records page.")
    else:
        print("⚠️ Unexpected redirect. Flash messages or errors may be present.")
        
        # Print flash or error messages
        alerts = driver.find_elements(By.CLASS_NAME, "alert")
        for alert in alerts:
            print("⚠️ Flash message:", alert.text)
        
        errors = driver.find_elements(By.CLASS_NAME, "text-danger")
        for err in errors:
            print(" -", err.text)

except Exception as e:
    driver.save_screenshot("add_record_error.png")
    print("❌ Exception during test:", e)

finally:
    driver.quit()
