import hmac
import hashlib
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from random import choice
from string import ascii_letters, digits
import binascii
import random
import string
from backports.pbkdf2 import pbkdf2_hmac


# Desencripta las contraseñas de los pares nombre de la app - password
def m_decrypt(jinput, key):
    try:
        load = json.loads(jinput)
        jkeys = ['nonce', 'header', 'ciphertext', 'tag']
        jvalues = {x: b64decode(load[x]) for x in jkeys}
        mycipher = AES.new(key.encode(), AES.MODE_GCM, nonce=jvalues['nonce'])
        mycipher.update(jvalues['header'])
        plaintext = mycipher.decrypt_and_verify(jvalues['ciphertext'], jvalues['tag'])
        return plaintext.decode('utf-8')
    except Exception as e:

        print('Error en la desencriptación')


# Encripta las contraseñas de los pares nombre de la app - password
def m_encrypt(text, key):
    cab = str.encode(''.join([choice(ascii_letters + digits) for x in range(8)]))
    plaintext = str.encode(text)
    mycipher = AES.new(key, AES.MODE_GCM)
    mycipher.update(cab)
    ciphertext, tag = mycipher.encrypt_and_digest(plaintext)
    jkeys = ['nonce', 'header', 'ciphertext', 'tag']
    jvalues = [b64encode(x).decode('utf-8') for x in (mycipher.nonce, cab, ciphertext, tag, key)]
    return json.dumps(dict(zip(jkeys, jvalues)))


# Genera un string aleatorio
def generate_random_string(size, seed=None):
    if seed != None:
        random.seed(seed)
    return ''.join(random.choice(string.ascii_letters) for i in range(size))


# Crea los hmac de los nombres de las aplicaciones
def create_hmac_sha256_signature(key, message):
    byte_key = binascii.unhexlify(key)
    message = str(message).encode()
    return hmac.new(byte_key, message, hashlib.sha256).hexdigest().upper()


# Compara strings y previene los timing attack
def slow_equals(val1, val2):
    diff = len(val1) ^ len(val2)
    i = 0
    while i < len(val2) and i < len(val1):
        diff |= (ord(val2[i]) ^ ord(val1[i]))
        i += 1
    return diff == 0

# Acumula el valor del producto entre la posición y el valor ascii de cada letra o dígito en una cadena de string
def sumOrd(val):
    total = 0
    pos = 1
    for i in val:
        total += pos * ord(i)
        pos += 1
    return total

def generate_derivation(masterPass, seed, num):
    salt = binascii.unhexlify(seed)
    key = pbkdf2_hmac('sha256', str.encode(masterPass), salt, 100000 + 500 * num, 32)
    return binascii.hexlify(key).decode('utf-8')
