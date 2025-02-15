import os, random, shelve, base64, getpass
from mailer import Mailer
from string import punctuation as punct
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import InvalidToken
from tkinter import *
import hashlib

salt = b'H\xed}\xbf\x0f\x8e\xc8\xbaL\xe2^J_\xa1\xe5\xf1'

def encrypt_database(master_password):
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=390000,)

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

def decrypt_database(master_password):
  kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=390000,)

  key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
  f = Fernet(key)
  try:
    with open('database', 'rb') as database:
      encrypted_database = database.read()

    decrypted_database = f.decrypt(encrypted_database)

    with open('database', 'wb') as database:
      database.write(decrypted_database)

  except FileNotFoundError:
    with open('database.dir', 'rb') as database:
      encrypted_database = database.read()

    decrypted_database = f.decrypt(encrypted_database)

    with open('database.dir', 'wb') as database:
      database.write(decrypted_database)

def two_factor_authentication(user_email):
  otp = ''.join([str(random.randint(0,9)) for _ in range(6)])
  email = Mailer(email="vault.project.otp@gmail.com",password="fhrc tvwb gjhw wjgv")
  email.send(receiver=user_email,subject="Vault Two-Factor Authentication code.",message=f"Your two-factor authentication code for Vault password manager is {otp}")
  input_otp = input("Enter the code that was sent to your email: ")
  if input_otp == otp:
    return True
  else :
    input_otp = input("Invalid OTP. Try again, re enter the code that was sent to your email: ")
    if input_otp == otp:
      return True
    else:
      return False


def verify_master_password(master_password):
  try:
    hash_file = shelve.open('hash')
  except FileNotFoundError:
    hash_file = shelve.open('hash.db')

  if hashlib.sha256(master_password.encode()).hexdigest() == hash_file['masterpasshash']:
    hash_file.close()
    return True
  else:
    hash_file.close()
    return False

def strong_pswd(pswd):
  upper_test = any([char.isupper() for char in pswd])
  lower_test = any([char.islower() for char in pswd])
  num_test = any([char.isdigit() for char in pswd])
  symb_test = any([char in punct for char in pswd])
  return all((upper_test, lower_test, num_test, symb_test))


print('Welcome to Vault!')
input_master_password = getpass.getpass('Please enter your master password to continue: ')

while not verify_master_password(input_master_password):
	input_master_password = getpass.getpass('Incorrect master password, try again to continue: ')
print('Correct master password!')

decrypt_database(input_master_password)
database = shelve.open('database')
email = database['email']
while not two_factor_authentication(email):
  print('Invalid OTP. A new code was sent to your email, check your inbox.')
print('Login successful!')
encrypt_database(input_master_password)

root = Tk()
root.withdraw()

main_menu = True
while main_menu:
	print('Choose one of the following options to continue (enter 1, 2 or 3): ')
	print('''1)Generate new password ,store it, and copy it to the clipboard.\n2)Store custom password.\n3)Retrieve password and copy it to clipboard.''')
	choice = input('Enter number: ')
	while choice not in ('1','2','3'):
		print('Invalid option. Enter 1, 2 or 3.')
		print('''1)Generate new password ,store it, and copy it to the clipboard.\n2)Store custom password.\n3)Retrieve password and copy it to clipboard.''')
		choice = input('Enter number: ')

	if choice == '1':
		website_password = ''.join([chr(random.randint(33,127)) for _ in range(12)])
		print('Password generated!')
		website_name = input('Enter the website name to save the password under: ')
		decrypt_database(input_master_password)
		database = shelve.open('database')
		database[website_name] = website_password
		database.close()
		encrypt_database(input_master_password)
		print(f'Password saved under the name {website_name}!')
		root.clipboard_clear()
		root.clipboard_append(website_password)
		print('Password copied to clipboard!')
	elif choice == '2':
		website_name = input('Enter the website name to save your custom password under: ')
		website_password = getpass.getpass('Enter your custom password: ')
		decrypt_database(input_master_password)
		database = shelve.open('database')
		database[website_name] = website_password
		database.close()
		encrypt_database(input_master_password)
		print(f'Custom password saved under the name {website_name}')
	elif choice == '3':
		decrypt_database(input_master_password)
		database = shelve.open('database')
		print("Choose a name or number to retrieve it's password: ")
		for ind, name in (ind_name:=list(enumerate(database))[1:]):
			print(f'{ind}) {name}')
		website_name = input('Enter website name or number to retrieve password: ')
		print(f'******ind_name = {ind_name}')
		name_num_lst = [j for i in ind_name for j in i]
		print(f'******name_num_lst = {name_num_lst}')
		if website_name.isdigit():
			website_name = int(website_name)
		while website_name not in name_num_lst:
			website_name = input('Invalid choice. Please enter one of the website names or their corresponding numbers: ')
			if website_name.isdigit():
				website_name = int(website_name)
		if isinstance(website_name, int):
			website_name = ind_name[int(website_name)-1][1]
			print(f'*****website_name derived = {website_name}')
		root.clipboard_clear()
		root.clipboard_append(database[website_name])
		database.close()
		encrypt_database(input_master_password)
		print(f'Password under the name {website_name} copied to clipboard!')

	option = input('Enter 0 for main menu or 1 to exit: ')
	while option not in ('0','1'):
		option = input('Invalid option. Enter 0 for main menu or 1 to exit: ')
  
	if option == '0':
		continue
	elif option == '1':
		main_menu = False
print('Goodbye... Thank you for using Vault Password Manager.')