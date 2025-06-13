from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import time

options = Options()
options.add_argument("--headless")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")

driver = webdriver.Chrome(options=options)

try:
    driver.get("http://localhost:5000/register")
    time.sleep(2)

    driver.find_element(By.ID, "username").send_keys("ciuser")
    driver.find_element(By.ID, "email").send_keys("ci@example.com")
    driver.find_element(By.ID, "password").send_keys("TestPass123")

    driver.find_element(By.ID, "first_name").send_keys("Test")
    driver.find_element(By.ID, "last_name").send_keys("Bot")
    driver.find_element(By.ID, "gender").send_keys("Male")
    driver.find_element(By.ID, "age").send_keys("25")
    driver.find_element(By.ID, "date_of_birth").send_keys("2000-01-01")

    driver.find_element(By.XPATH, '//button[@type="submit"]').click()
    time.sleep(2)

    assert "Please log in" in driver.page_source or "already exists" in driver.page_source
finally:
    driver.quit()
