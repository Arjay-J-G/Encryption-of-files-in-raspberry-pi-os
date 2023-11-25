import os
import subprocess
import wave
import numpy as np
from cryptography.fernet import Fernet
from stegano import lsb


def encrypt_text(text, password):                      
    cipher_suite = Fernet(password)
    encrypted_text = cipher_suite.encrypt(text.encode())
    return encrypted_text
    
def decrypt_text(encrypted_text, password):                             #decrypting text
    cipher_suite = Fernet(password)
    decrypted_text = cipher_suite.decrypt(encrypted_text)
    return decrypted_text.decode()


def encrypt_text_file(file_path):                                       #encrypt text file
    with open(file_path, 'rb') as file:
        data = file.read()

    password = Fernet.generate_key()
    os.environ['ENCRYPTION_KEY'] = password.decode()  # Storing the key which is retrieved later to decrypt

    cipher_suite = Fernet(password)
    encrypted_data = cipher_suite.encrypt(data)

    with open('encrypted_text_file.txt', 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)

    print("Text file encrypted successfully.")
    
    
def decrypt_text_file(encrypted_file_path):                              #decrypt text file
    with open(encrypted_file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()

    password = os.environ.get('ENCRYPTION_KEY')   #retrieving the key which is stored when encrypting

    if password:
        cipher_suite = Fernet(password.encode())  
        decrypted_data = cipher_suite.decrypt(encrypted_data)

        decrypted_file_path = encrypted_file_path.replace('encrypted_text_file.txt', 'decrypted_text_file.txt')
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        print("File decrypted successfully.")
    else:
        print("Encryption key not found in environment variables.")

   

def openssl_encrypt(data, password):                                                           #hiding the text file in a image
    openssl_command_encrypt = f'echo "{data}" | openssl enc -e -aes-256-cbc -base64 -k "{password}"'
    encrypted_data = subprocess.check_output(openssl_command_encrypt, shell=True)
    return encrypted_data.decode().strip()


def hide_data_in_image(data_to_hide, image_path):
    secret = lsb.hide(image_path, data_to_hide)
    secret.save('encrypted_image.png')
    print("Data encrypted and stored in the image successfully.")


def extract_data_from_image(image_path):                                    #retrieving the text file from the encrypted image
    secret = lsb.reveal(image_path)
    return secret
 
def openssl_decrypt(encrypted_data, password):
    openssl_command_decrypt = f'echo "{encrypted_data}" | openssl enc -d -aes-256-cbc -base64 -k "{password}"'
    decrypted_data = subprocess.check_output(openssl_command_decrypt, shell=True)
    return decrypted_data.decode().strip()




#MAIN FUNCTION    

while True:
   
    print("Menu:")
    print("1. Encrypt text")
    print("2. Encrypt text file")
    print("3. Hide text file in Image")
    print("4. Decrypt the text")
    print("5. Decrypt the text file")
    print("6. Decrypt the text file hidden in the image")
    print("7. Exit")
    
    
    choice = input("Enter your choice (1-7): ")
    
    
    if choice == "1":
        text_to_encrypt = input("Enter the text to encrypt: ")
        password = Fernet.generate_key()

        encrypted_text = encrypt_text(text_to_encrypt, password)
        print(f"Encrypted Text: {encrypted_text.decode()}")
        
    elif choice == "2":
    
    	file_path = '/home/arjayrasp/MPMCProject/sample_text_file'     #the file path where the text file is present should be given here
    	encrypt_text_file(file_path)
        
        
      

    elif choice == "3":
    
        data_to_encrypt = "Secret information"
        password = "Pwd"                                          #THIS PASSWORD CAN BE SET BY USER ALSO BY TAKING IT AS INPUT

        encrypted_data = openssl_encrypt(data_to_encrypt, password)
        print(f"Encrypted Data: {encrypted_data}")
        image_path = 'rasp.jpg'  
        hide_data_in_image(encrypted_data, image_path)
        
    elif choice == "4":
        decrypted_text = decrypt_text(encrypted_text, password)
        print(f"Decrypted Text: {decrypted_text}")

        
    elif choice == "5":
        encrypted_file_path = 'encrypted_text_file.txt'  
        decrypt_text_file(encrypted_file_path) 
        
    elif choice == "6":
    
        image_with_hidden_data_path = 'encryped_image.png'  

        hidden_data = extract_data_from_image(image_with_hidden_data_path)
        password = "Pwd"                       

        decrypted_data = openssl_decrypt(hidden_data, password)
        print(f"Decrypted Data: {decrypted_data}")
     
    elif choice == "7":
        print("EXITING THE ENCRYPTION SOFTWARE...")
        break  
        
    else:
        print("Invalid choice. Please enter a valid option (1-7).")

