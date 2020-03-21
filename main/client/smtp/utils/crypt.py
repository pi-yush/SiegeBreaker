
import cPickle
import random

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


import os
import base64

import seccure

CONTR_PUBLIC_KEYPATH = '../keys/public.pem'
CONTR_PRIVATE_KEYPATH = '../keys/private.pem'




def get_key_path(path):
    try:
        return open(path)
    except Exception as e:
        return open('../' + path)




def clean_public_key_obj(public_key):
    g = RSA.importKey(get_key_path(CONTR_PUBLIC_KEYPATH).read())
    g.key = public_key
    return g;


def get_ec_public_private_key():
    ec_priv_key, ec_pub_key = seccure.generate_keypair()
    return ec_pub_key , ec_priv_key


def test_ec_crypto():
    q,p = seccure.generate_keypair()
    c = seccure.encrypt(b'ABC' ,  p)
    print seccure.decrypt(c , q)





def seccure_get_encrypted_content(plain_text , public_key):
    cipher_text = seccure.encrypt(plain_text, public_key)
    return base64.encodestring(cipher_text)


def seccure_get_decrypted_content(cipher_text , private_key):
    cipher_text = base64.decodestring(cipher_text)
    plain_text = seccure.decrypt(cipher_text, private_key)
    return plain_text



def get_encrypted_content(plain_text , public_key = None):

    if public_key is None:
        public_key = RSA.importKey(get_key_path(CONTR_PUBLIC_KEYPATH).read())

    cipher_rsa = PKCS1_OAEP.new(public_key)
    cipher_text= cipher_rsa.encrypt(plain_text)
    return base64.encodestring(cipher_text)


def get_decrypted_content(encrypted_content , private_key = None ):

    if private_key is None:
        private_key = RSA.importKey(get_key_path(CONTR_PRIVATE_KEYPATH).read())

    encrypted_content = base64.decodestring( encrypted_content )

    cipher_rsa = PKCS1_OAEP.new(private_key)
    plain_text = cipher_rsa.decrypt(encrypted_content)
    return plain_text




if __name__ == '__main__':
    test_ec_crypto()
    a = get_encrypted_content("abc")
    print(get_decrypted_content(a))