import cryptography
from cryptography.fernet import Fernet

def ballot_tracker_generation():
    ballot_tracker = Fernet.generate_key()
    return ballot_tracker

def ballot_encoding(message,ballot_tracker):
    encoded = message.encode()
    f = Fernet(ballot_tracker)
    encrypted = f.encrypt(encoded)
    return encrypted

def ballot_decoding(encrypted, ballot_tracker):
    f = Fernet(ballot_tracker)
    decrypted = f.decrypt(encrypted)
    return decrypted.decode()

#ballot_tracker = ballot_tracker_generation()
#print("ballot_tracker: ",ballot_tracker)
#message = "ABC"
#encrypted = ballot_encoding(message,ballot_tracker)
#print("encrypted: ",encrypted)
#decrypted_message = ballot_decoding(encrypted, ballot_tracker)
#print("decrypted_message: ",decrypted_message)

#......................................................................................
#message = input("What is your deep dark secret:")
#encoded = message.encode()
#print(encoded)

#f = Fernet(key1)
#print(f)
#encrypted = f.encrypt(encoded)
#print(encrypted)

#f = Fernet(key1)
#print(f)
#decrypted = f.decrypt(encrypted)
#print(decrypted)
#
#message1 = decrypted.decode()
#print(message1)