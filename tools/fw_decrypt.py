#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Decryption Tool

"""
import argparse
import json
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
import base64
from pwnlib.util.packing import u16

def decrypt_firmware(infile: str, outfile: str, secret_file: str):
    # Load protected firmware binary from infile
    with open(infile, mode="rb") as fp:
        protected_firmware = fp.read()

    # Read secrets as a JSON file
    with open(secret_file, mode="r") as fp:
        secrets = json.load(fp)

    # Extract AES IV and ciphertext
    aes_iv = protected_firmware[:16]
    aes_ciphertext = protected_firmware[16:]

    # Decode AES key from base64
    aes_key = base64.b64decode(secrets["aes_key"])

    # Initialize AES with IV and decrypt ciphertext
    aes = AES.new(aes_key, AES.MODE_CBC, iv=aes_iv)
    decrypted_blob = aes.decrypt(aes_ciphertext)

    # Remove padding
    decrypted_blob = unpad(decrypted_blob, AES.block_size)

    # Extract and verify Ed25519 signature
    firmware_blob = decrypted_blob[:-64]
    signature = decrypted_blob[-64:]
    ed25519_public_key = ECC.import_key(base64.b64decode(secrets["ed25519_public_key"]))
    verifier = eddsa.new(ed25519_public_key, mode='fips-186-3')

    try:
        verifier.verify(firmware_blob, signature)
        print("Ed25519 signature verification passed.")
    except ValueError:
        print("Ed25519 signature verification failed.")
        return

    # Extract version, size, and release message
    version = u16(firmware_blob[:2], endian='little')
    size = u16(firmware_blob[2:4], endian='little')
    release_message = firmware_blob[size + 4:-1].decode('ascii')

    # Write decrypted firmware to outfile
    with open(outfile, mode="wb") as out_fp:
        out_fp.write(firmware_blob[4:size + 4])

    print(f"Version: {version}\nFirmware Size: {size} bytes\nRelease Message: {release_message}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Decryption Tool")
    parser.add_argument(
        "--infile", help="Path to the firmware image to decrypt.", required=True)
    parser.add_argument(
        "--outfile", help="Filename for the output decrypted firmware.", required=True)
    parser.add_argument(
        "--secrets", help="Path to the secrets JSON file.", required=True)
    args = parser.parse_args()

    decrypt_firmware(infile=args.infile, outfile=args.outfile, secret_file=args.secrets)