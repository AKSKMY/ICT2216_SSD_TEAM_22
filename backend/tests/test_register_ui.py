from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import time

options = Options()
options.add_argument("--headless")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")
options.binary_location = "/usr/bin/chromium-browser"
driver = webdriver.Chrome(options=options)
driver.get("http://localhost:5000/register")

try:
    # Fill in the form fields
    driver.find_element(By.ID, "username").send_keys("testuser")
    driver.find_element(By.ID, "email").send_keys("testuser@example.com")
    driver.find_element(By.ID, "password").send_keys("Password123")

    driver.find_element(By.ID, "first_name").send_keys("Test")
    driver.find_element(By.ID, "last_name").send_keys("User")

    gender_dropdown = Select(driver.find_element(By.ID, "gender"))
    gender_dropdown.select_by_visible_text("Other")

    driver.find_element(By.ID, "age").send_keys("22")
    driver.find_element(By.ID, "date_of_birth").send_keys("2002-01-01")

    # Scroll to submit button and click
    submit_button = driver.find_element(By.XPATH, '//button[@type="submit"]')
    driver.execute_script("arguments[0].scrollIntoView({behavior: 'smooth', block: 'center'});", submit_button)
    time.sleep(1)
    driver.execute_script("arguments[0].click();", submit_button)

    # Wait briefly for post-submission redirect or flash messages
    time.sleep(2)

    # Optional: take screenshot to debug in CI
    driver.save_screenshot("register_result.png")

    print("✅ Form submitted successfully.")

except Exception as e:
    driver.save_screenshot("register_error.png")
    print(f"❌ Test failed: {e}")

finally:
    driver.quit()
