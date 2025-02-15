import os
print('Installing requirements...\n')
os.system('pip install cryptography email_validator quick-mailer')
print('All requirements installed successfully!\n\n')

import shelve, getpass, base64, re, random, hashlib
from mailer import Mailer
from string import punctuation as punct
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def strong_pswd(pswd):
	upper_test = any([char.isupper() for char in pswd])
	lower_test = any([char.islower() for char in pswd])
	num_test = any([char.isdigit() for char in pswd])
	symb_test = any([char in punct for char in pswd])
	return all((upper_test, lower_test, num_test, symb_test))

def get_email():
  email_pattern = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
  email = input('Enter your email: ')
  email_confirm = input('Confirm your email: ')

  while email != email_confirm or not re.match(email_pattern, email):
    if email != email_confirm:
      print('Emails do not match.')
    else:
      print('Invalid email.')
    email = input('Enter your email again: ')
    email_confirm = input('Confirm your email: ')
  return email

def email_verification_code(user_email):
	otp = ''.join([str(random.randint(0,9)) for _ in range(6)])
	email = Mailer(email="vault.project.otp@gmail.com",password="fhrc tvwb gjhw wjgv")
	email.send(receiver=user_email,subject="Vault Email Verification code.",message=f"Your verification code for Vault password manager is {otp}")
	input_otp = input("Enter the email verification code that was sent to your email: ")
	if input_otp == otp:
		return True
	else :
		input_otp = input("Invalid code, Try again, re enter the email verification code that was sent to your email: ")
		if input_otp == otp:
			return True
		else:
			return False

print("Let's setup your master password! (the password used to access your password manager)")
master_password = getpass.getpass('Enter your master password (include uppercase letters, lowercase letters, numbers, and special characters): ')
master_password_confirm = getpass.getpass('Confirm your master password: ')

while master_password != master_password_confirm or not strong_pswd(master_password):
	if master_password != master_password_confirm:
		print('Passwords do not match.')
	else:
		print('Password not strong enough.')
	master_password = getpass.getpass('Enter your master password again: ')
	master_password_confirm = getpass.getpass('Confirm your master password: ')
print('Master password setup successfully!')

master_password_hash = hashlib.sha256(master_password.encode()).hexdigest()
hash_file = shelve.open('hash')
hash_file['masterpasshash'] = master_password_hash
hash_file.close()

print("Now, let's setup your 2FA email address!")
email = get_email()
print('An email verification code was sent to your email. Check your inbox.')
while not email_verification_code(email):
	print('Incorrect email verification code.\nChoose an option: ')
	print("1)Resend the code.\n2)Change your email address (you don't have access to the email you entered).")
	choice = input()
	if choice == '1':
		continue
	else:
		email = get_email()
print('Email Verified Successfully!')
print("You're all set!")

database = shelve.open('database')
database['email'] = email
database.close()

salt = b'H\xed}\xbf\x0f\x8e\xc8\xbaL\xe2^J_\xa1\xe5\xf1'
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=390000,
)
key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
f = Fernet(key)
try:
  with open('database', 'rb') as database:
    original_database = database.read()

  encrypted_database = f.encrypt(original_database)

  with open('database', 'wb') as database:
    database.write(encrypted_database)
except FileNotFoundError:
  with open('database.dir', 'rb') as database:
    original_database = database.read()

  encrypted_database = f.encrypt(original_database)

  with open('database.dir', 'wb') as database:
    database.write(encrypted_database)