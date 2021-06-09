import sqlite3
import os
import glob
import json
import base64
import shutil

try:
    import win32crypt
    from Crypto.Cipher import AES
except:
    pass

os_env = os.environ["USERPROFILE"] + os.sep

PATH = {
    "Chrome": glob.glob(f"{os_env}/AppData/Local/Google/Chrome/User Data/*/Login Data"),
    "ChromeKeyPath": glob.glob(
        f"{os_env}/AppData/Local/Google/Chrome/User Data/Local State"
    ),
    "Edge": glob.glob(f"{os_env}/AppData/Local/Microsoft/Edge/User Data/*/Login Data"),
    "EdgeKeyPath": glob.glob(
        f"{os_env}/AppData/Local/Microsoft/Edge/User Data/Local State"
    ),
}


def decrypt(encryptedValue, key=None):
    try:
        # for over 80 version chrome
        iv = encryptedValue[3:15]
        payload = encryptedValue[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted = cipher.decrypt(payload)
        decrypted = decrypted[:-16].decode()  # remove suffix bytes
        return decrypted
    except:
        # chrome version under 80
        under_80_password = win32crypt.CryptUnprotectData(
            encryptedValue, None, None, None, 0
        )[1]
        return under_80_password.decode()


def get_aes_key(keyPath):
    with open(keyPath, "rt", encoding="UTF8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)
    aes_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    aes_key = aes_key[5:]  # removing DPAPI
    aes_key = win32crypt.CryptUnprotectData(aes_key, None, None, None, 0)[1]

    return aes_key


def pwd_extraction(safeStorageKey, loginData):
    decrypted_list = []

    shutil.copy2(loginData, "./login_vault.db")

    with sqlite3.connect("./login_vault.db") as database:
        cursor = database.cursor()
        db_items = cursor.execute(
            "SELECT username_value, password_value, origin_url FROM logins"
        )

    for username, encrypted_pass, url in db_items.fetchall():
        if encrypted_pass and len(username) > 0:
            decrypted_list.append(
                {
                    "origin_url": url,
                    "username": username,
                    "password": decrypt(encrypted_pass, safeStorageKey),
                }
            )

    return decrypted_list


if __name__ == "__main__":
    # color setting ANSI
    default = "\033[0m"
    green = "\033[32m"
    blue = "\033[34m"
    bold = "\033[1m"

    browser_type = "Chrome"
    login_data = PATH.get(browser_type)
    key_path = PATH.get(browser_type + "KeyPath")[0]

    for profile in login_data:
        for i, info in enumerate(pwd_extraction(get_aes_key(key_path), f"{profile}")):
            print(
                f"{green}[{(i + 1)}]{default}{bold} \n"
                f"URL:   {str(info['origin_url'])} \n"
                f"User:  {str(info['username'])} \n"
                f"Pwd:   {str(info['password'])} \n {default}"
            )
