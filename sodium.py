import ctypes
from ctypes import *

sodium = cdll.LoadLibrary("libsodium.so")

crypto_box_MACBYTES = 16
crypto_box_PUBLICKEYBYTES = 32
crypto_box_SEALBYTES = crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES

crypto_box_SECRETKEYBYTES = 32

crypto_sign_PUBLICKEYBYTES = 32
crypto_sign_SECRETKEYBYTES = 32 + 32
crypto_sign_BYTES = 64

crypto_aead_ABYTES = 16
crypto_aead_NPUBBYTES = 8
crypto_aead_KEYBYTES = 32

crypto_scalarmult_BYTES = 32

crypto_generichash_BYTES = 32

sodium.crypto_box_keypair.argtypes = [c_char_p, c_char_p]
sodium.crypto_sign_keypair.argtypes = [c_char_p, c_char_p]
sodium.crypto_sign.argtypes = [c_char_p, POINTER(c_longlong), c_char_p, c_longlong, c_char_p]
sodium.crypto_sign_open.argtypes = [c_char_p, POINTER(c_longlong), c_char_p, c_longlong, c_char_p]
sodium.crypto_sign_detached.argtypes = [c_char_p, POINTER(c_longlong), c_char_p, c_longlong, c_char_p]
sodium.crypto_sign_verify_detached.argtypes = [c_char_p, c_char_p, c_longlong, c_char_p]
sodium.crypto_aead_chacha20poly1305_encrypt.argtypes = [c_char_p, POINTER(c_longlong), c_char_p, c_longlong, c_char_p, c_longlong, c_char_p, c_char_p, c_char_p]
sodium.crypto_aead_chacha20poly1305_decrypt.argtypes = [c_char_p, POINTER(c_longlong), c_char_p, c_char_p, c_longlong, c_char_p, c_longlong, c_char_p, c_char_p]
sodium.crypto_box_seal.argtypes = [c_char_p, c_char_p, c_longlong, c_char_p]
sodium.crypto_box_seal_open.argtypes = [c_char_p, c_char_p, c_longlong, c_char_p, c_char_p]

class SodiumException(Exception): pass
class InvalidMessage(SodiumException): pass
class InvalidSignature(SodiumException): pass

def urandom(n):
    with open("/dev/urandom","r") as f:
        return f.read(n)

def crypto_box_keypair():
    pk = create_string_buffer(crypto_box_PUBLICKEYBYTES)
    sk = create_string_buffer(crypto_box_SECRETKEYBYTES)
    sodium.crypto_box_keypair(pk, sk)
    return (pk.raw, sk.raw)

def crypto_box_seal(message, pk):
    sealed_message = create_string_buffer(len(message) + crypto_box_SEALBYTES)
    sodium.crypto_box_seal(sealed_message, message, len(message), pk)
    return sealed_message.raw

def crypto_box_seal_open(sealed_message, sk, pk):
    assert len(sealed_message) >= crypto_box_SEALBYTES
    message = create_string_buffer(len(sealed_message) - crypto_box_SEALBYTES)
    sodium.crypto_box_seal_open(message, sealed_message, len(sealed_message), pk, sk)
    return message.raw

def crypto_sign_keypair():
    pk = create_string_buffer(crypto_sign_PUBLICKEYBYTES)
    sk = create_string_buffer(crypto_sign_SECRETKEYBYTES)
    sodium.crypto_sign_keypair(pk, sk)
    return (pk.raw, sk.raw)

def crypto_sign(message, sk):
    assert len(sk) == crypto_sign_SECRETKEYBYTES
    signed_message = create_string_buffer(crypto_sign_BYTES + len(message))
    signed_message_len = ctypes.c_longlong()
    sodium.crypto_sign(signed_message, byref(signed_message_len), message, len(message), sk)
    return signed_message.raw

def crypto_sign_open(signed_message, pk):
    assert len(pk) == crypto_sign_PUBLICKEYBYTES
    assert len(signed_message) >= crypto_sign_BYTES
    message = create_string_buffer(len(signed_message) - crypto_sign_BYTES)
    message_len = c_longlong()
    if sodium.crypto_sign_open(message, byref(message_len), signed_message, len(signed_message), pk)  != 0:
        raise InvalidMessage()
    return message.raw

def crypto_sign_detached(message, sk):
    assert len(sk) == crypto_sign_SECRETKEYBYTES
    signature = create_string_buffer(crypto_sign_BYTES)
    signature_len = c_longlong()
    sodium.crypto_sign_detached(signature, byref(signature_len), message, len(message), sk)
    return signature.raw

def crypto_sign_verify_detached(signature, message, pk):
    assert len(signature) == crypto_sign_BYTES
    assert len(pk) == crypto_sign_PUBLICKEYBYTES
    return sodium.crypto_sign_verify_detached(signature, message, len(message), pk) == 0

def crypto_aead_encrypt(message, key, npub):
    assert len(npub) == crypto_aead_NPUBBYTES
    assert len(key) == crypto_aead_KEYBYTES
    encrypted_message = create_string_buffer(crypto_aead_ABYTES + len(message))
    encrypted_message_len = c_longlong()
    sodium.crypto_aead_chacha20poly1305_encrypt(
            encrypted_message, byref(encrypted_message_len),
            message, len(message),
            None, 0,
            None,
            npub, key)
    return encrypted_message.raw

def crypto_aead_decrypt(encrypted_message, key, npub):
    assert len(npub) == crypto_aead_NPUBBYTES
    assert len(key) == crypto_aead_KEYBYTES
    assert len(encrypted_message) >= crypto_aead_ABYTES
    message = create_string_buffer(len(encrypted_message) - crypto_aead_ABYTES)
    message_len = c_longlong()
    if sodium.crypto_aead_chacha20poly1305_decrypt(
            message, byref(message_len),
            None,
            encrypted_message, len(encrypted_message),
            None, 0,
            npub, key) != 0:
         raise InvalidMessage()
    return message.raw

def crypto_scalarmult_base(secret):
    assert len(secret) == crypto_scalarmult_BYTES
    public = create_string_buffer(crypto_scalarmult_BYTES)
    sodium.crypto_scalarmult_base(public, secret)
    return public.raw

def crypto_scalarmult(secret, public):
    assert len(secret) == crypto_scalarmult_BYTES
    assert len(public) == crypto_scalarmult_BYTES
    shared_secret = create_string_buffer(crypto_scalarmult_BYTES)
    sodium.crypto_scalarmult(shared_secret, secret, public)
    return shared_secret.raw

def crypto_generichash(data, key=None):
    generichash = create_string_buffer(crypto_generichash_BYTES)
    key_len = len(key) if key else 0
    sodium.crypto_generichash(generichash, crypto_generichash_BYTES, data, len(data), key, key_len)
    return generichash.raw

def keyexchange_init(secret):
    return crypto_scalarmult_base(secret)

def keyexchange_generate_secret(secret, public):
    shared_secret = crypto_scalarmult(secret, public)
    return crypto_generichash(shared_secret)

if sodium.sodium_init() != 0:
    print "Could not initilize libsodium!"
#    exit(1)

verbose = True

if __name__ == "__main__":
    print "== crypto sign key generaton test =="
    pk, sk = crypto_sign_keypair()
    if verbose:
        print "Secret key:", sk.encode("hex")
        print "Public key:", pk.encode("hex")
    print "Test OK"

    print "== crypto sign test =="
    m = urandom(100)
    sm = crypto_sign(m, sk)
    m2 = crypto_sign_open(sm, pk)
    assert m == m2
    print "Test OK"

    print "== crypto sign detached test =="
    sig = crypto_sign_detached(m, sk)
    m2 = crypto_sign_verify_detached(sig, m, pk)
    assert m == m2
    print "Test OK"

    print "== crypto aead test =="
    key = urandom(32)
    nonce = urandom(8)
    cm = crypto_aead_encrypt(m, key, nonce)
    m2 = crypto_aead_decrypt(cm, key, nonce)
    assert m == m2
    print "Test OK"

    print "== crypto box key generation test =="
    pk, sk = crypto_box_keypair()
    if verbose:
        print "Secret key:", sk.encode("hex")
        print "Public key:", pk.encode("hex")
    print "Tet OK"

    print "== crypto_box test =="
    sm = crypto_box_seal(m, pk)
    m2 = crypto_box_seal_open(sm, sk, pk)
    assert m == m2
    print "Test OK"

    print "== key exchange test == "
    sk1 = urandom(crypto_scalarmult_BYTES)
    pk1 = keyexchange_init(sk1)
    if verbose:
        print "Secret1 key:", sk1.encode("hex")
        print "Public1 key:", pk1.encode("hex")
    sk2 = urandom(crypto_scalarmult_BYTES)
    pk2 = keyexchange_init(sk2)
    if verbose:
        print "Secret2 key:", sk2.encode("hex")
        print "Public2 key:", pk2.encode("hex")
    ss1 = keyexchange_generate_secret(sk1, pk2)
    ss2 = keyexchange_generate_secret(sk2, pk1)
    assert ss1 == ss2
    if verbose:
        print "Shared secret:", ss1.encode("hex")
    print "Test OK"

