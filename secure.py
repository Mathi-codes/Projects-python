from cryptography.fernet import Fernet
def create_key():                                                                   # To create key for encryption and decryption
    try : 
        key=Fernet.generate_key()                                                   # Generating a key
        key_container=open("mykeynow.key","wb")                                 
        key_container.write(key)                                                    # write the key to a file
    except Exception as e:
        error_logging("Key creation :" + str(e))
def encrypt():                                                                      # To encrypt user details...
    try : 
        open_key=open("mykeynow.key","rb")
        key=open_key.read()                                                         # save the key in a variable called key
        f=Fernet(key)
        content=open("User details.txt","rb")
        original=content.read()                                                     # Save all the user details in original
        encrypted=f.encrypt(original)                                               # encrypt the content in original and store it in encrypted
        encrypt_file_now=open("encrypted_file_now","wb")
        encrypt_file_now.write(encrypted)                                           # write the encrypted content in a new file
    except Exception as e:
        error_logging("Encrypting :" + str(e))
def decrypt():                                                                      # To decrypt user details...
    try :
        open_key=open("mykeynow.key","rb")
        key=open_key.read()                                                         # save the key in a variable called key
        f=Fernet(key)
        content=open("encrypted_file_now","rb")
        original=content.read()                                                     # Save all the user details in original
        decrypted=f.decrypt(original)                                               # decrypt the content in original and store it in decrypted
        decrypted_file_now=open("decrypted_file_now","wb")
        decrypted_file_now.write(decrypted)                                         # write the decrypted content in a new file                                         
    except Exception as e:
        error_logging("Decrypting :" + str(e))
