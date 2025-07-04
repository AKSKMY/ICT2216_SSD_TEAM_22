from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

# --- CONFIG ---
URL = "http://localhost:5000/auth/register"
EXPECTED_REDIRECT = "http://localhost:5000/auth/login"
CHROME_PATH = "/usr/bin/chromium-browser"  # Update if needed

# --- SETUP CHROME HEADLESS DRIVER ---
options = Options()
options.add_argument("--headless")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")
options.binary_location = CHROME_PATH
driver = webdriver.Chrome(options=options)

try:
    driver.get(URL)
    wait = WebDriverWait(driver, 10)

    # Ensure page loads and form is visible
    wait.until(EC.presence_of_element_located((By.ID, "username")))

    # Fill account credentials
    driver.find_element(By.ID, "username").send_keys("TestUser")
    driver.find_element(By.ID, "email").send_keys("selenium@gmail.com")
    driver.find_element(By.ID, "password").send_keys("Strong@Password$456")

    # Fill personal info
    driver.find_element(By.ID, "first_name").send_keys("Selenium")
    driver.find_element(By.ID, "last_name").send_keys("Tester")

    gender_dropdown = Select(driver.find_element(By.ID, "gender"))
    gender_dropdown.select_by_visible_text("Other")

    date_value = "1995-05-10"
    driver.execute_script(f"document.getElementById('date_of_birth').value = '{date_value}'")

    # Submit form
    submit_button = driver.find_element(By.XPATH, '//button[@type="submit"]')
    driver.execute_script("arguments[0].scrollIntoView(true);", submit_button)
    time.sleep(0.5)
    submit_button.click()

    # Wait for potential redirect
    time.sleep(2)

    # ✅ Compare against expected URL
    current_url = driver.current_url
    print("🔗 Final URL:", current_url)

    if current_url == EXPECTED_REDIRECT:
        print("✅ Registration test passed: Redirected to login page.")
    else:
        print("⚠️ Registration failed or did not redirect correctly.")
        # Print any error messages
        errors = driver.find_elements(By.CLASS_NAME, "text-danger")
        for err in errors:
            print(f" - {err.text}")

except Exception as e:
    driver.save_screenshot("register_error.png")
    print(f"❌ Test exception: {e}")

finally:
    driver.quit()
