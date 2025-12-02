import os
from cryptography.fernet import Fernet
from getpass import getpass

forbidden = ['/', '\\', '..', '~', ':', ';', '|', '&', '>', '<']

def sanitize(name):
    if any(char in name for char in forbidden):
        return False, "Invalid website name"
    if len(name) > 50:
        return False, "Website name too long"
    return True, name  

while True:
    action = input("Enter 'c' to create, 'r' to retrieve, 'q' to quit, 'd' to delete or 't' to dev test (c/r/q/d/t): ").strip().lower()

    if action == 'q':
    # Quit the program
        print("Goodbye!")
        break


    elif action == 'd':
        DEL_FILE = input("What file do you want to delete? ")
        is_valid, result = sanitize(DEL_FILE)  # Fixed: capture return values
        if not is_valid:
            print(result)  # Print the error message
            continue
        DEL_FILE = result  # Use the sanitized name
        if os.path.exists(DEL_FILE):
            try:
                if os.path.exists(DEL_FILE):  # Check if it's a file before attempting to remove
                    os.remove(DEL_FILE)
                    print(f"The file {DEL_FILE} was successfully deleted.")
            except PermissionError:
                print(f"Error: You do not have permission to delete {DEL_FILE}.")
            except Exception as e:
                print(f"An unexpected error occurred: {e}")
        else:
            print(f"Error: The file {DEL_FILE} does not exist.")

    if action == 'r':
        # Retrieve existing password
        USER_WEB = input("Which website file do you want the password from? ")
        is_valid, result = sanitize(USER_WEB)  # Fixed: capture return values
        if not is_valid:
            print(result)  # Print the error message
            continue
        USER_WEB = result  # Use the sanitized name
        enc_path = USER_WEB
        key_path = USER_WEB + '_key'
        # Check files exist
        if not os.path.exists(enc_path):
            print(f"Encrypted file '{enc_path}' not found.")
            continue
        if not os.path.exists(key_path):
            print(f"Key file '{key_path}' not found.")
            continue

        # Permission check: ensure key file is owned by the current user
        try:
            key_stat = os.stat(key_path)
            if hasattr(os, 'getuid') and key_stat.st_uid != os.getuid():
                print("You do not have permission to access this key file (owner mismatch).")
                continue
        except Exception:
            pass

        # Try opening key file
        try:
            with open(key_path, 'rb') as kf:
                key = kf.read()
        except PermissionError:
            print("Permission denied when accessing key file.")
            continue
        except Exception as e:
            print(f"Failed to read key file: {e}")
            continue

        # Read encrypted password
        try:
            with open(enc_path, 'rb') as ef:
                encrypted = ef.read()
        except Exception as e:
            print(f"Failed to read encrypted file: {e}")
            continue

        # Decrypt and print
        try:
            f = Fernet(key)
            decrypted = f.decrypt(encrypted).decode('utf-8')
            print(f"Password for '{USER_WEB}': {decrypted}")
        except Exception as e:
            print(f"Failed to decrypt password: {e}")
            continue

    elif action == 'c':
        # Create new password
        USER_PWD = getpass("what password do you want to save: ")
        is_valid, result = sanitize(USER_PWD)  # Fixed: capture return values
        if not is_valid:
            print(result)  # Print the error message
            continue
        USER_PWD = result  # Use the sanitized name
        # encrypt the password
        key = Fernet.generate_key()
        f = Fernet(key)
        ENCRYPT_PWD = f.encrypt(USER_PWD.encode())

        # ask what website is this password used for 
        USER_WEB = input("what website is this password for ")
        is_valid, result = sanitize(USER_WEB)  # Fixed: capture return values
        if not is_valid:
            print(result)  # Print the error message
            continue
        USER_WEB = result  # Use the sanitized name

        # create a file for the website and save encrypted password
        enc_path = USER_WEB
        key_path = USER_WEB + '_key'

        # If files already exist, confirm overwrite
        overwrite = 'y'  # Default to yes
        if os.path.exists(enc_path) or os.path.exists(key_path):
            overwrite = input(f"Files for '{USER_WEB}' already exist. Overwrite? (y/n): ").strip().lower()
        if overwrite != 'y':
            with open(enc_path, 'wb') as file:
                file.write(ENCRYPT_PWD)
        
        # Save the key in a separate file
        key_path = USER_WEB + '_key'
        with open(key_path, 'wb') as key_file:
            key_file.write(key)

        # Restrict permissions: owner read/write only (0o600)
        try:
            os.chmod(USER_WEB, 0o600)
            os.chmod(key_path, 0o600)
        except Exception:
            pass
        
        print(f"Password saved for {USER_WEB}")

    elif action == 't':
        # Dev test area
        print("")
        continue