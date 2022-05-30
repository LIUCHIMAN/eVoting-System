from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def generateKey():
    #Getting a Key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def storing_privkey(private_key):
    #Storing Keys - private_key
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    print("Private Key:" ,pem.decode())
    #with open('private_key.pem', 'wb') as f:
    #    f.write(pem)

def storing_pubvkey(public_key):
    #Storing Keys - public_key
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("Public Key:" ,pem.decode())
    #with open('public_key.pem', 'wb') as f:
    #    f.write(pem)

def reading_privkey(private_key):
    #Reading Keys - private_key
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

def reading_pubkey(public_key):
    #Reading Keys - public_key
    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

def encrypt_message(message,public_key):
    #Encrypting
    encode_message = message.encode()
    encrypted = public_key.encrypt(
        encode_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_message(encrypted,private_key):
    #Decrypting
    original_message = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return original_message

#..........................................................................
#message = input("Please input your secert message: ")
#keys = generateKey()
#encrypted = encrypt_message(message,keys[1])
#print(encrypted)
#original_message = decrypt_message(encrypted,keys[0])
#print(original_message.decode())