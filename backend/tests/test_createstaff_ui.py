from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import uuid

# --- CONFIG ---
LOGIN_URL = "http://localhost:5000/test-login-admin"
CREATE_URL = "http://localhost:5000/doctor/createAccount"
LOGOUT_URL = "http://localhost:5000/auth/logout"
CHROME_PATH = "/usr/bin/chromium-browser"

# Generate a unique username and email each run to avoid duplicate user error
unique_suffix = uuid.uuid4().hex[:6]
username = f"teststaff_{unique_suffix}"
email = f"{username}@example.com"

# --- SETUP ---
options = Options()
options.add_argument("--headless")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")
options.binary_location = CHROME_PATH
driver = webdriver.Chrome(options=options)

try:
    wait = WebDriverWait(driver, 10)

    # ✅ 1. Login as admin
    driver.get(LOGIN_URL)
    wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))
    print("✅ Logged in via test-login-admin")

    # ✅ 2. Go to Create Account page
    driver.get(CREATE_URL)
    wait.until(EC.presence_of_element_located((By.ID, "username")))

    # ✅ 3. Fill the form
    driver.find_element(By.ID, "username").send_keys(username)
    driver.find_element(By.ID, "email").send_keys(email)
    driver.find_element(By.ID, "password").send_keys("TestPassword123")
    driver.find_element(By.ID, "role").send_keys("Doctor")

    driver.find_element(By.ID, "first_name").send_keys("Test")
    driver.find_element(By.ID, "last_name").send_keys("User")
    driver.find_element(By.ID, "age").send_keys("35")
    driver.find_element(By.ID, "gender").send_keys("Female")

    submit_button = driver.find_element(By.XPATH, '//button[@type="submit"]')
    driver.execute_script("arguments[0].scrollIntoView(true);", submit_button)
    time.sleep(0.5)
    submit_button.click()

    # ✅ 4. Wait for the flash message
    wait.until(EC.presence_of_element_located((By.CLASS_NAME, "alert")))
    alerts = driver.find_elements(By.CLASS_NAME, "alert")

    success_found = False
    for alert in alerts:
        print("🔔 Flash message:", alert.text)
        if "account created successfully" in alert.text.lower():
            success_found = True

    if success_found:
        print("✅ Admin staff creation test passed.")
    else:
        print("❌ Flash message did not confirm successful account creation.")

    # ✅ 5. Logout after test
    print("🚪 Logging out...")
    driver.get(LOGOUT_URL)

    # Confirm logout success
    if "login" in driver.current_url or "logged out" in driver.page_source.lower():
        print("✅ Successfully logged out after test.")
    else:
        print("⚠️ Could not confirm logout.")

except Exception as e:
    print("❌ Exception during test:", e)

finally:
    driver.quit()
