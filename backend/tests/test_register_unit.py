import pytest
from bs4 import BeautifulSoup
from unittest.mock import patch
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import app as flask_app


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    flask_app.config["WTF_CSRF_ENABLED"] = False
    with flask_app.test_client() as client:
        yield client

def extract_flash_messages(response):
    soup = BeautifulSoup(response.data, 'html.parser')
    return [li.text.strip() for li in soup.select("ul.text-danger li")]

# ───────────────────────────────────────────────────────
# ✅ VALIDATION TESTS
# ───────────────────────────────────────────────────────

def test_password_too_short(client):
    res = client.post("/register", data={
        "username": "shortpass",
        "email": "short@example.com",
        "password": "123",
        "first_name": "Short",
        "last_name": "Pass",
        "gender": "Male",
        "age": "22",
        "date_of_birth": "2000-01-01"
    })
    messages = extract_flash_messages(res)
    assert "Password must be at least 8 characters." in messages

def test_invalid_username_format(client):
    res = client.post("/register", data={
        "username": "!!!bad***",
        "email": "test@example.com",
        "password": "Password123",
        "first_name": "Test",
        "last_name": "User",
        "gender": "Female",
        "age": "30",
        "date_of_birth": "1995-01-01"
    })
    messages = extract_flash_messages(res)
    assert "Username must be 3–20 characters long and alphanumeric (underscores allowed)." in messages

def test_invalid_email_format(client):
    res = client.post("/register", data={
        "username": "validuser",
        "email": "invalid-email",
        "password": "Password123",
        "first_name": "Valid",
        "last_name": "User",
        "gender": "Other",
        "age": "25",
        "date_of_birth": "1990-01-01"
    })
    messages = extract_flash_messages(res)
    assert "Please enter a valid email address." in messages

def test_pwned_password(client):
    with patch("app.is_password_pwned", return_value=True):
        res = client.post("/register", data={
            "username": "breacheduser",
            "email": "pwned@example.com",
            "password": "Password123",
            "first_name": "Breach",
            "last_name": "Test",
            "gender": "Male",
            "age": "32",
            "date_of_birth": "1991-01-01"
        })
        messages = extract_flash_messages(res)
        assert "This password has appeared in a data breach." in messages[0]

def test_missing_name(client):
    res = client.post("/register", data={
        "username": "nonameuser",
        "email": "no@example.com",
        "password": "Good@Pass123",
        "first_name": "",
        "last_name": "",
        "gender": "Female",
        "age": "20",
        "date_of_birth": "2003-01-01"
    })
    messages = extract_flash_messages(res)
    assert "First name and last name are required." in messages

def test_invalid_gender(client):
    res = client.post("/register", data={
        "username": "badgender",
        "email": "badgender@example.com",
        "password": "Good@Pass123",
        "first_name": "Test",
        "last_name": "User",
        "gender": "Unknown",
        "age": "25",
        "date_of_birth": "1999-01-01"
    })
    messages = extract_flash_messages(res)
    assert "Please select a valid gender." in messages

def test_invalid_age(client):
    res = client.post("/register", data={
        "username": "badage",
        "email": "badage@example.com",
        "password": "Good@Pass123",
        "first_name": "Test",
        "last_name": "User",
        "gender": "Male",
        "age": "-5",
        "date_of_birth": "1990-01-01"
    })
    messages = extract_flash_messages(res)
    assert "Age must be a positive number." in messages

def test_future_date_of_birth(client):
    res = client.post("/register", data={
        "username": "futureuser",
        "email": "future@example.com",
        "password": "Good@Pass123",
        "first_name": "Future",
        "last_name": "Person",
        "gender": "Other",
        "age": "22",
        "date_of_birth": "2099-01-01"
    })
    messages = extract_flash_messages(res)
    assert "Date of birth cannot be in the future." in messages

def test_invalid_date_format(client):
    res = client.post("/register", data={
        "username": "baddate",
        "email": "baddate@example.com",
        "password": "Good@Pass123",
        "first_name": "Date",
        "last_name": "Error",
        "gender": "Male",
        "age": "30",
        "date_of_birth": "31-12-1990"  # Wrong format
    })
    messages = extract_flash_messages(res)
    assert "Invalid date format" in messages[0]

if __name__ == "__main__":
    import pytest
    pytest.main([__file__])
