# Vault Password Manager

Vault is a **secure password manager** that encrypts and stores your passwords locally. It features **AES-based encryption**, **two-factor authentication (2FA) via email**, and a **master password** for access.

## Features
- **Master Password Protection** - Secure login using a SHA-256 hashed master password.  
- **Two-Factor Authentication (2FA)** - Email-based verification for added security.  
- **AES Encryption** - Uses PBKDF2HMAC and Fernet encryption to protect stored passwords.  
- **Password Generator** - Generates strong random passwords.  
- **Clipboard Integration** - Copies retrieved passwords to the clipboard for easy use.  
- **Local Storage** - Passwords are stored locally, ensuring user privacy.

---

## Installation

### **Step 1: Clone the Repository**
```sh
git clone https://github.com/yourusername/Vault-Password-Manager.git
cd Vault-Password-Manager
```

### **Step 2: Run the Setup Script**
```sh
python setup.py
```
This will:
- Install necessary dependencies.
- Prompt you to set up a **master password**.
- Configure your **2FA email**.
- Encrypt your password database.

---

## Usage

### **Starting the Password Manager**
Run the following command:
```sh
python main.py
```

### **Login Process**
1. Enter your **master password**.
2. A **6-digit OTP code** will be sent to your **registered email**.
3. Enter the OTP to access your passwords.

### **Main Menu Options**
1️⃣ **Generate & Store a New Password**  
- A **random 12-character password** is created and stored under a website name.  
- The password is **copied to the clipboard**.  

2️⃣ **Store a Custom Password**  
- Manually store a password under a specific website name.  

3️⃣ **Retrieve a Stored Password**  
- Select a **website name or index number** to retrieve its password.  
- The password is **copied to the clipboard**.

---

## Security Measures
- **Master Password Encryption** - The master password is hashed using **SHA-256**.  
- **Database Encryption** - All passwords are encrypted with **AES-based Fernet encryption**.  
- **Two-Factor Authentication (2FA)** - Prevents unauthorized access via email verification.  
- **Clipboard-Based Password Retrieval** - Passwords are **never displayed on screen**.

---

## Dependencies
The following libraries are required and automatically installed:
```sh
pip install cryptography email_validator quick-mailer
```
