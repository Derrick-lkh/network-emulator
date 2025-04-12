from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import json
import ast
import binascii


class VPN:
    def __init__(self):
        self.private, self.public, self.public_key_str = self.generate_ECDH_keys()
        self.shared_secret = None
        # self.party_public_key = None # another party pub key
        self.encryption_key = None
        pass

    def generate_ECDH_keys(self):
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        party_public_key_str = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")
        return private_key, public_key, party_public_key_str

    def generate_shared_secret(self, party_public_key_str):
        party_public_key = serialization.load_pem_public_key(
            party_public_key_str.encode()
        )
        print("KEY", party_public_key)
        shared_secret = self.private.exchange(ec.ECDH(), party_public_key)
        self.shared_secret = shared_secret
        self.derive_encryption_key(shared_secret)
        return shared_secret

    def derive_encryption_key(self, shared_secret):
        # Deriving a symmetric encryption key from the shared secret
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes = 256-bit key for AES-256
            salt=None,  # Optional: Can use a known salt for extra security
            info=b"handshake data",  # Context-specific identifier
        )

        encryption_key = hkdf.derive(shared_secret)  # Final encryption key
        self.encryption_key = encryption_key
        return encryption_key

    def encrypt_data(self, data):
        """
        Encrypts the provided data using AES-GCM.
        Assumes `self.encryption_key` has already been derived using HKDF from the shared secret.

        :param data: The data (plaintext) to be encrypted (bytes)
        :return: ciphertext (bytes), IV (nonce), and authentication tag
        """

        # Ensure data is in bytes if it's in string form
        if isinstance(data, str):
            data = data.encode()

        # Generate a random IV (Nonce) for AES-GCM (12 bytes recommended)
        iv = os.urandom(12)

        # Encrypt with AES-GCM
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.GCM(iv))
        encryptor = cipher.encryptor()

        # Encrypt the data
        ciphertext = encryptor.update(data) + encryptor.finalize()

        # Authentication tag (generated with GCM mode)
        tag = encryptor.tag

        print(f"🔐 Encrypted Message: {ciphertext.hex()}")
        print(f"📌 IV: {iv.hex()}")
        print(f"✅ Authentication Tag: {tag.hex()}")

        # Return ciphertext, IV, and tag for later use (decryption)
        return ciphertext, iv, tag

    def decrypt_data(self, ciphertext_hex, iv_hex, tag_hex):
        """
        Decrypts the provided ciphertext using AES-GCM.
        Assumes `self.encryption_key` has already been derived using HKDF from the shared secret.

        :param ciphertext: The encrypted data (bytes) to be decrypted
        :param iv: The initialization vector (nonce) used during encryption
        :param tag: The authentication tag used during encryption
        :return: The decrypted plaintext (bytes)
        """
        ciphertext = binascii.unhexlify(ciphertext_hex)
        iv = binascii.unhexlify(iv_hex)
        tag = binascii.unhexlify(tag_hex)

        # Decrypt with AES-GCM
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()

        try:
            # Decrypt the ciphertext
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            print(
                f"🛡️ Decrypted Message: {plaintext.decode()}"
            )  # Assuming the plaintext was originally a UTF-8 string
            return plaintext
        except Exception as e:
            print(f"❌ Decryption failed: {str(e)}")
            return None

    ## Generate packet data
    def packet_auth_key_exchange_data(self):
        data = {
            "message_type": "VPN_AUTH_KEY_EXCHANGE",
            "public_key": f"{self.public_key_str}",
        }
        return json.dumps(data)


def main():
    clientVPN = VPN()
    serverVPN = VPN()

    # client_pub = clientVPN.public_key_str
    # server_pub = serverVPN.public_key_str

    # shared_c = clientVPN.generate_shared_secret(server_pub)
    # shared_s = serverVPN.generate_shared_secret(client_pub)
    # print(shared_c)
    # print(shared_s)

    # ciphertext, iv, tag = clientVPN.encrypt_data("hello")
    # print(ciphertext, iv, tag)
    # decrypted_msg = serverVPN.decrypt_data(ciphertext, iv, tag)
    # print(decrypted_msg)

    client_pub_packet = clientVPN.packet_auth_key_exchange_data()
    server_pub_packet = serverVPN.packet_auth_key_exchange_data()
    # print(client_pub_packet)
    # print(server_pub_packet)

    # Exchange over the wire

    ## CLIENT SIDE
    client_pub_packet_decode = json.loads(server_pub_packet)
    client_pub = client_pub_packet_decode.get("public_key")
    print(client_pub)
    # Gen shared
    c_shared = clientVPN.generate_shared_secret(client_pub)
    print(c_shared)
    cipher_message_str = clientVPN.packet_encrypted_message("Hello")
    # ciphertext, iv, tag = clientVPN.encrypt_data("hello")
    # print(ciphertext, iv, tag)

    ## SERVER SIDE
    server_pub_packet_decode = json.loads(client_pub_packet)
    server_pub = server_pub_packet_decode.get("public_key")
    print(server_pub)
    # Gen shared
    s_shared = serverVPN.generate_shared_secret(server_pub)
    print(s_shared)

    message_data = json.loads(cipher_message_str)
    print(message_data)
    # message_type = message_data['message_type']
    nonce_str = message_data["Nonce"]
    ciphertext_str = message_data["Ciphertext"]
    auth_tag_str = message_data["AuthTag"]
    import ast

    nonce = ast.literal_eval(nonce_str)
    ciphertext = ast.literal_eval(ciphertext_str)
    auth_tag = ast.literal_eval(auth_tag_str)

    decrypted_msg = serverVPN.decrypt_data(ciphertext, nonce, auth_tag)
    print(decrypted_msg)

    # shared_c = clientVPN.generate_shared_secret(server_pub)
    # shared_s = serverVPN.generate_shared_secret(client_pub)


if __name__ == "__main__":
    main()
