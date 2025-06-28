import os
import re
from dotenv import load_dotenv
load_dotenv()  # loads .env file automatically\
from flask import current_app
import pymysql
from datetime import datetime, date, timedelta
import hashlib
import random
import requests

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
from config import secret


# ───────────────────────────────────────────────────────
# Functions
# ───────────────────────────────────────────────────────
def get_db():
    return pymysql.connect(
        host=current_app.config["DB_HOST"],
        user=current_app.config["DB_USER"],
        password=current_app.config["DB_PASSWORD"],
        database=current_app.config["DB_NAME"],
        port=3306,
        cursorclass=pymysql.cursors.DictCursor
    )

def has_permission(user_id, permission_name):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT 1
            FROM user u
            JOIN userrole ur ON u.user_Id = ur.user_Id
            JOIN rolepermission rp ON ur.role_Id = rp.role_Id
            JOIN permission p ON rp.permission_Id = p.permission_Id
            WHERE u.user_Id = %s AND p.permission_name = %s
            LIMIT 1
        """, (user_id, permission_name))
        return cur.fetchone() is not None


def log_action(user_id, description):
    try:
        # Encrypt the description with Admin KEK
        encrypted_description = encrypt_with_kek(description.encode("utf-8"), 3)

        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO rbac.audit_log (user_Id, description)
                VALUES (%s, %s)
            """, (user_id, encrypted_description))
        conn.commit()
    except Exception as e:
        print("Audit log error:", e)
    finally:
        conn.close()


def is_password_pwned(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    if response.status_code != 200:
        return False  # Assume safe if the API fails
    hashes = (line.split(":") for line in response.text.splitlines())
    return any(s == suffix for s, _ in hashes)


# Use master key to decrypt encrypted KEK to obtain KEK so it can be used
def decrypt_with_master_key(encoded_encrypted: str, master_key: bytes) -> bytes:
    aesgcm = AESGCM(master_key)
    encrypted = base64.b64decode(encoded_encrypted)

    nonce = encrypted[:12]
    ciphertext = encrypted[12:]

    return aesgcm.decrypt(nonce, ciphertext, None)


# Get encrypted kek from critical database according to kek_id
def get_encrypted_kek_from_db(kek_id):
    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT kek_value FROM critical.kek WHERE kek_id = %s", (kek_id,))
        result = cursor.fetchone()
        if result is None:
            raise ValueError(f"KEK with id {kek_id} not found in the database.")
        return result['kek_value']  # the base64 string
    finally:
        cursor.close()


# Use kek to encrypt the plaintext in order to store it
def encrypt_with_kek(plaintext: bytes, kek_id: int):
    try:
        master_key = base64.b64decode(secret('KEK_MASTER_KEY'))
        encrypted_kek = get_encrypted_kek_from_db(kek_id)
        dec_kek = decrypt_with_master_key(encrypted_kek, master_key)
        if not dec_kek:
            print("❌ Failed to decrypt KEK.")
            return None
        aesgcm = AESGCM(dec_kek)
        nonce = os.urandom(12)
        encrypted = aesgcm.encrypt(nonce, plaintext, None)
        return base64.b64encode(nonce + encrypted).decode("utf-8")
    except Exception as e:
        return (f"❌ Error! Check with admin")


# Create AES key that is encrypted with appropriate KEK
def create_encrypted_aes_key(kek_id):
    aes_key = os.urandom(32)
    return encrypt_with_kek(aes_key, kek_id)


# Create RSA key that is encrypted with appropriate KEK
def create_encrypted_RSA_key():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_b64 = base64.b64encode(public_bytes).decode('utf-8')
    return encrypt_with_kek(private_bytes, 2), public_key_b64


def get_encrypted_key(user_id, user_role):
    conn = get_db()
    cursor = conn.cursor()
    try:
        if (user_role == "Doctor"):
            cursor.execute("SELECT private_enc_key FROM critical.doctor_priv_key WHERE doctor_id = %s", (user_id,))
            result = cursor.fetchone()
            if result is None:
                raise ValueError(f"KEK with id {user_id} not found in the database.")
            return result['private_enc_key']  # the base64 string
        elif (user_role == "Patient"):
            cursor.execute("SELECT patient_AES_key FROM critical.patient_encryption_key WHERE patient_id = %s",
                           (user_id,))
            result = cursor.fetchone()
            if result is None:
                raise ValueError(f"KEK with id {user_id} not found in the database.")
            return result['patient_AES_key']  # the base64 string
        elif (user_role == "Admin"):
            cursor.execute("SELECT admin_AES_key FROM critical.admin_encryption_key WHERE id = %s", (user_id,))
            result = cursor.fetchone()
            if result is None:
                raise ValueError(f"KEK with id {user_id} not found in the database.")
            return result['admin_AES_key']  # the base64 string
        else:
            print("Your role does not have a key.")
    finally:
        cursor.close()


def decrypt_with_aes(enc_key, dec_kek):
    encrypted = base64.b64decode(enc_key)
    nonce = encrypted[:12]
    ciphertext = encrypted[12:]
    aesgcm = AESGCM(dec_kek)
    return aesgcm.decrypt(nonce, ciphertext, None)


def encrypt_with_aes_key(aes_key, plaintext):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def encrypt_medical_records(patient_id, plaintext):
    try:
        master_key = base64.b64decode(secret('KEK_MASTER_KEY'))
        encrypted_kek = get_encrypted_kek_from_db(1)
        dec_kek = decrypt_with_master_key(encrypted_kek, master_key)
        enc_key = get_encrypted_key(patient_id, "Patient")
        patient_key = decrypt_with_aes(enc_key, dec_kek)
        return encrypt_with_aes_key(patient_key, plaintext)
    except Exception as e:
        return (f"❌ Error! Check with admin")


def decrypt_AES_cipher(ciphertext, user_id, user_role):
    try:
        master_key = base64.b64decode(secret('KEK_MASTER_KEY'))
        if user_role == "Patient":
            user_role_number = 1
        elif user_role == "Admin":
            user_role_number = 3
        encrypted_kek = get_encrypted_kek_from_db(user_role_number)
        dec_kek = decrypt_with_master_key(encrypted_kek, master_key)
        enc_key = get_encrypted_key(user_id, user_role)
        user_key = decrypt_with_aes(enc_key, dec_kek)
        return decrypt_with_aes(ciphertext, user_key).decode("utf-8")
    except Exception as e:
        return (f"❌ Error! Check with admin")


# Function to view table for debugging
def view_table_data(table_name):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(f"SELECT * FROM {table_name}")
        rows = cur.fetchall()
        print(f"\n📋 Data in `{table_name}`:")
        for row in rows:
            print(row)
    except Exception as e:
        print(f"❌ Error reading table `{table_name}`:", e)
    finally:
        cur.close()

def decrypt_admin_log(ciphertext):
    try:
        master_key = base64.b64decode(secret('KEK_MASTER_KEY'))
        encrypted_kek = get_encrypted_kek_from_db(3)  # Admin KEK
        dec_kek = decrypt_with_master_key(encrypted_kek, master_key)
        return decrypt_with_aes(ciphertext, dec_kek).decode("utf-8")
    except Exception as e:
        return "❌ Error decrypting log"
    
def sign_medical_record(doctor_id, diagnosis, patient_id, date):
    try:
        master_key = base64.b64decode(secret('KEK_MASTER_KEY'))
        encrypted_kek = get_encrypted_kek_from_db(2)
        dec_kek = decrypt_with_master_key(encrypted_kek, master_key)
        enc_private_key = get_encrypted_key(doctor_id, "Doctor")
        private_key = decrypt_with_aes(enc_private_key, dec_kek)

        to_sign = f"{diagnosis}|{patient_id}|{doctor_id}|{date}".encode("utf-8")
        signature = private_key.sign(
            to_sign,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode("utf-8")
    except Exception as e:
        return "❌ Error signing"

def derive_public_key(doctor_id):
    # Step 1: Load master key
    master_key = base64.b64decode(secret('KEK_MASTER_KEY'))

    # Step 2: Decrypt KEK (assume doctor kek_id is 2)
    encrypted_kek = get_encrypted_kek_from_db(2)
    dec_kek = decrypt_with_master_key(encrypted_kek, master_key)

    # Step 3: Decrypt private RSA key
    encrypted_priv_key = get_encrypted_key(doctor_id, "Doctor")
    priv_key_bytes = decrypt_with_aes(encrypted_priv_key, dec_kek)

    # Step 4: Load private key object
    private_key = serialization.load_pem_private_key(
        priv_key_bytes,
        password=None,
    )

    # Step 5: Extract public key in PEM format
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(public_pem).decode('utf-8')