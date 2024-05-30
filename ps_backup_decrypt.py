import argparse
from io import BytesIO

from Crypto.Cipher import AES
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap_with_padding
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_der_public_key
from cryptography.x509 import load_der_x509_certificate

# Observed with ProtectToolkit C Key Management Utility 5.9.1
# TODO test the other file backup versions mentioned in https://thalesdocs.com/gphsm/ptk/5.9.1/docs/Content/PTK-C_Admin/CLI_Ref/CTKMU.htm
BACKUP_VERSION = b"\x00\x00\x02\x0D"

parser = argparse.ArgumentParser()
parser.add_argument('--file-backup', type=str, help='The path to the file backup', required=True)
# TODO support wrapping keys other than AES
# TODO support receiving the key from components interactively
parser.add_argument('--aes-wrapping-key', type=str, help='The AES wrapping key in hexadecimal', required=True)
args = parser.parse_args()

with open(args.file_backup, "rb") as f:
    backup_feature_version = f.read(4)
    if backup_feature_version != BACKUP_VERSION:
        raise ValueError(f"Unknown version of the Backup Feature")
    f.read(4)  # Skip the length of the Encoded Payload
    objs_num = int.from_bytes(f.read(4))
    objs_encrypted = []
    for _ in range(objs_num):
        object_len = int.from_bytes(f.read(4))
        object_bytes = BytesIO(f.read(object_len))
        encrypted_obj_len = int.from_bytes(object_bytes.read(4))
        encrypted_obj = object_bytes.read(encrypted_obj_len)
        object_bytes.read(4)  # Discard the attributes structure length
        attrs_num = int.from_bytes(object_bytes.read(4))
        attr_class = None
        attr_label = None
        attr_key_type = None
        for _ in range(attrs_num):
            attr_type = int.from_bytes(object_bytes.read(4))
            attr_len = int.from_bytes(object_bytes.read(4))
            attr_present = object_bytes.read(1)  # content presence indicator
            if attr_present == b"\x01":
                attr_value = object_bytes.read(attr_len)
            else:
                attr_value = None
            # Process known attributes
            if attr_type == 0:  # CKA_CLASS
                attr_class = int.from_bytes(attr_value)
            if attr_type == 3:  # CKA_LABEL
                if attr_value is not None:
                    attr_label = attr_value.decode("utf-8")
                else:
                    attr_label = ""
            if attr_type == 0x00000100:  # CKA_KEY_TYPE
                attr_key_type = int.from_bytes(attr_value)
        # TODO understand what are exactly the following 8 bytes. There is nothing on this on https://thalesdocs.com/gphsm/ptk/5.9.1/docs/Content/PTK-C_Program/PTK-C_Mechs/CKM_WRAPKEY_AES_KWP.htm
        object_bytes.read(8)
        objs_encrypted.append({"encrypted_obj": encrypted_obj, "attr_class": attr_class, "attr_label": attr_label,
                               "attr_key_type": attr_key_type})
    f.read(4)  # Discard MAC of the Payload
    f.read(int.from_bytes(f.read(4)))  # Discard Encoded MAC key and its length
    enc_transport_key = f.read(int.from_bytes(f.read(4)))
    transport_key = aes_key_unwrap_with_padding(bytes.fromhex(args.aes_wrapping_key), enc_transport_key)
    for i, obj_enc in enumerate(objs_encrypted, start=1):
        obj_bytes = aes_key_unwrap_with_padding(transport_key, obj_enc["encrypted_obj"])
        print(f"{i} - Processing object with label '{obj_enc['attr_label']}'...")
        if obj_enc["attr_class"] == 0x00000001:  # CKO_CERTIFICATE
            print("  Certificate.")
            certificate = load_der_x509_certificate(obj_bytes)
            print(f"  Subject: {certificate.subject.rfc4514_string()}")
            print(f"  Issuer: {certificate.issuer.rfc4514_string()}")
            print(f"  Serial number: {certificate.serial_number}")
            print(f"  Not valid before: {certificate.not_valid_before_utc}")
            print(f"  Not valid after: {certificate.not_valid_after_utc}")
            certificate = certificate.public_bytes(encoding=serialization.Encoding.PEM)
            obj_bytes = certificate
        elif obj_enc["attr_class"] == 0x00000002:  # CKO_PUBLIC_KEY
            if obj_enc["attr_key_type"] == 0x00000000:  # CKK_RSA
                print("  RSA public key.")
                rsa_public_key = load_der_public_key(obj_bytes)
                print(f"  Modulus: {rsa_public_key.public_numbers().n:x}")
                print(f"  Public exponent: {rsa_public_key.public_numbers().e:x}")
                # FIXME redundant code similar to this below. Refactor for reuse. Maybe I could load the key objects generically using methods like `load_der_public_key`, falling back to `key_bytes`. 
                public_bytes = rsa_public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                           format=serialization.PublicFormat.SubjectPublicKeyInfo)
                obj_bytes = public_bytes
            elif obj_enc["attr_key_type"] == 0x00000003:  # CKK_ECDSA
                print("  ECDSA public key.")
                ec_public_key = load_der_public_key(obj_bytes)
                ec_public_numbers = ec_public_key.public_numbers()
                print(f"  Public key (x): {ec_public_numbers.x:x}")
                print(f"  Public key (y): {ec_public_numbers.y:x}")
                print(f"  Curve: {ec_public_key.curve.name}")
                ec_public_key = ec_public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                           format=serialization.PublicFormat.SubjectPublicKeyInfo)
                obj_bytes = ec_public_key
        if obj_enc["attr_class"] == 0x00000003:  # CKO_PRIVATE_KEY
            if obj_enc["attr_key_type"] == 0x00000000:  # CKK_RSA
                print("  RSA private key.")
                rsa_private_key = load_der_private_key(obj_bytes, password=None)
                print(f"  Modulus: {rsa_private_key.private_numbers().public_numbers.n:x}")
                print(f"  Public exponent: {rsa_private_key.private_numbers().public_numbers.e:x}")
                print(f"  Private exponent: {rsa_private_key.private_numbers().d:x}")
                rsa_private_key = rsa_private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                                encryption_algorithm=serialization.NoEncryption(),
                                                                format=serialization.PrivateFormat.TraditionalOpenSSL)
                obj_bytes = rsa_private_key
            elif obj_enc["attr_key_type"] == 0x00000003: # CKK_ECDSA
                print("  ECDSA private key.")
                ec_private_key = load_der_private_key(obj_bytes, password=None)
                print(f"  Private key: {ec_private_key.private_numbers().private_value:x}")
                key = ec_private_key.public_key()
                ec_public_numbers = ec_private_key.public_key().public_numbers()
                print(f"  Public key (x): {ec_public_numbers.x:x}")
                print(f"  Public key (y): {ec_public_numbers.y:x}")
                print(f"  Curve: {ec_private_key.curve.name}")
                ec_private_key = ec_private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                                encryption_algorithm=serialization.NoEncryption(),
                                                                format=serialization.PrivateFormat.TraditionalOpenSSL)
                obj_bytes = ec_private_key
        elif obj_enc["attr_class"] == 0x00000004:  # CKO_SECRET_KEY
            if obj_enc["attr_key_type"] == 0x0000001F:  # CKK_AES
                print("  AES secret key.")
                cipher = AES.new(obj_bytes, AES.MODE_ECB)
                # TODO check if 32 bytes is always enough.
                plaintext = bytes([0x00] * 32)
                encrypted = cipher.encrypt(plaintext)
                kcv = encrypted[:3].hex().upper()
                print(f"  KCV: {kcv}")
                obj_bytes = obj_bytes.hex().encode("utf-8")

        obj_file_path = f"obj_{i}_{obj_enc['attr_label']}"
        with open(obj_file_path, "wb") as obj_file:
            obj_file.write(obj_bytes)

        print(f"  Object with label '{obj_enc['attr_label']}' stored to file '{obj_file_path}'")
