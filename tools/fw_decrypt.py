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
from Crypto.Hash import HMAC, SHA512
import base64


def decrypt_firmware(infile: str, outfile: str, secret_file: str):
    #Load firmware binary from infile
    with open(infile, mode="rb") as fp:
        protected_firmware = fp.read()
    # Read secrets as a json file
    with open(secret_file, mode="r") as fp:
        secrets = json.load(fp)

    #Extract AES IV, ciphertext, and tag from infile 
    aes_iv = protected_firmware[:16]
    aes_ciphertext = protected_firmware[16:-16]
    aes_tag = protected_firmware[-16:]
    aes_key = base64.b64decode(secrets["aes_key"])

    #Initiliaze AES key in GCM mode
    aes = AES.new(aes_key, AES.MODE_GCM, nonce=aes_iv) 

    try:
        firmware_blob = aes.decrypt_and_verify(aes_ciphertext, aes_tag)
        print("AES decryption successful.")
    except ValueError:
        print("Decryption failed. Check the AES key.")
        return
    
    #Extract and verify the HMAC
    hmac_key = base64.b64decode(secrets["hmac_key"])
    prehash = firmware_blob[:-64]
    hmac_digest = firmware_blob[-64:]
    
    hmac = HMAC.new(hmac_key, digestmod=SHA512)
    hmac.update(prehash)
    
    try:
        hmac.verify(hmac_digest)
        print("HMAC verification passed.")
    except ValueError:
        print("HMAC verification failed. Check the HMAC key.")
        return
    
    #Extract signature and firmware and verify through ed25519 verification 
    firmware_blob = prehash[:-64]
    signature = prehash[-64:]
    ed25519_public_key = ECC.import_key(base64.b64decode(secrets["ed25519_public_key"]))
    verifier = eddsa.new(ed25519_public_key, mode='rfc8032')
    
    try:
        verifier.verify(firmware_blob, signature)
        print("Message is authentic, ed25519 signature verification passed.")
    except ValueError:
        print("The message is not authentic, ed25519 signature verification failed.")

    #Extract version, size, firmware, and release_message to be outputted
    version = u16(firmware_blob[:2], endian='little')
    size = u16(firmware_blob[2:4], endian='little')
    firmware = firmware_blob[4:size+4]
    release_message = firmware_blob[size+4:-1].decode('utf-8')
    
    # Write decrypted firmware into output file
    with open(outfile, mode="wb+") as fp:
        fp.write(firmware)
    
    print(f"Version: {version}\nFirmware Size: {size} bytes\nRelease Message: {release_message}")
    
    
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Decryption Tool")
    parser.add_argument(
        "--infile", help="Path to the firmware image to decrypt.", required=True)
    parser.add_argument(
        "--outfile", help="Filename for the output decrypted firmware.", required=True)
    parser.add_argument(
        "--secrets", help="Path to the secrets json file.", required=True)
    args = parser.parse_args()

    decrypt_firmware(infile=args.infile, outfile=args.outfile, secret_file=args.secrets)
