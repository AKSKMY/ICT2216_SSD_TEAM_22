from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

# --- CONFIG ---
URL = "http://localhost:5000/register"
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
    driver.find_element(By.ID, "username").send_keys("seleniumtestuser")
    driver.find_element(By.ID, "email").send_keys("selenium@example.com")
    driver.find_element(By.ID, "password").send_keys("StrongPassword123")

    # Fill personal info
    driver.find_element(By.ID, "first_name").send_keys("Selenium")
    driver.find_element(By.ID, "last_name").send_keys("Tester")

    gender_dropdown = Select(driver.find_element(By.ID, "gender"))
    gender_dropdown.select_by_visible_text("Other")

    driver.find_element(By.ID, "age").send_keys("30")
    driver.find_element(By.ID, "date_of_birth").send_keys("1995-05-10")

    # Submit form
    submit_button = driver.find_element(By.XPATH, '//button[@type="submit"]')
    driver.execute_script("arguments[0].scrollIntoView(true);", submit_button)
    time.sleep(0.5)
    submit_button.click()

    # Wait for redirect or flash message (up to 5 seconds)
    time.sleep(2)
    driver.save_screenshot("register_result.png")

    # Check if redirected to login page
    if "/login" in driver.current_url:
        print("✅ Registration test passed: Redirected to login page.")
    else:
        # Check for error message
        errors = driver.find_elements(By.CLASS_NAME, "text-danger")
        if errors:
            print("⚠️ Registration failed with validation errors:")
            for err in errors:
                print(f" - {err.text}")
        else:
            print("⚠️ Registration did not redirect but no visible errors.")
except Exception as e:
    driver.save_screenshot("register_error.png")
    print(f"❌ Test exception: {e}")
finally:
    driver.quit()
