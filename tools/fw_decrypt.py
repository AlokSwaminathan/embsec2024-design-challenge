#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Decryption Tool

"""
import argparse
from pwnlib.util.packing import u16
import json
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from Crypto.Util.Padding import unpad
import base64
from util import get_hex


def decrypt_firmware(infile: str, outfile: str, secret_file: str):
    #Load firmware binary from infile
    with open(infile, mode = "rb") as protected_binary:
        protected_firmware = protected_binary.read()
    # Read secrets as a json file
    with open(secret_file, mode = "r") as secrets_json:
        secrets = json.load(secrets_json)

    #Extract AES IV and ciphertext from infile 
    aes_iv = protected_firmware[:16]
    aes_ciphertext = protected_firmware[16:]
    aes_key = base64.b64decode(secrets["aes_key"])
    
    print(f"AES IV: {get_hex(aes_iv)}")
    
    print(f"AES Key: {get_hex(aes_key)}")

    #Initiliaze AES key in CBC mode
    aes = AES.new(aes_key, AES.MODE_CBC, IV=aes_iv) 

    # Decrypt the firmware
    try:
        signed_firmware_blob = unpad(aes.decrypt(aes_ciphertext), AES.block_size)
        print("AES decryption successful.")
    except ValueError:
        print("Decryption failed. Check the AES key.")
        return
    
    #Extract signature and firmware and verify through ed25519 verification 
    firmware_blob = signed_firmware_blob[:-64]
    signature = signed_firmware_blob[-64:]
    ed25519_public_key = ECC.import_key(base64.b64decode(secrets["ed25519_public_key"]),curve_name='ed25519')
    verifier = eddsa.new(ed25519_public_key, mode = 'rfc8032')
    
    try:
        verifier.verify(firmware_blob, signature)
        print("Message is authentic, ed25519 signature verification passed.")
    except ValueError:
        print("The message is not authentic, ed25519 signature verification failed.")

    #Extract version, size, firmware, and release_message to be outputted
    version = u16(firmware_blob[:2], endian = 'little')
    size = u16(firmware_blob[2:4], endian = 'little')
    firmware = firmware_blob[4:size + 4]
    release_message = firmware_blob[size + 4:-1].decode('ascii')
    
    # Write decrypted firmware into output file
    with open(outfile, mode = "wb+") as decrypted_binary:
        decrypted_binary.write(firmware)
    
    print(f"Version: {version}\nFirmware Size: {size} bytes\nRelease Message: {release_message}")
    
    
    
# parameters for compiling function in terminal
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description = "Firmware Decryption Tool")
    parser.add_argument(
        "--infile", help = "Path to the firmware image to decrypt.", required = True)
    parser.add_argument(
        "--outfile", help = "Filename for the output decrypted firmware.", required = True)
    parser.add_argument(
        "--secrets", help = "Path to the secrets json file.", required = False, default="secret_build_output.txt")
    args = parser.parse_args()

    decrypt_firmware(infile = args.infile, 
                     outfile = args.outfile, 
                     secret_file = args.secrets)