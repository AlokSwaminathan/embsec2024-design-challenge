#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
from pwnlib.util.packing import p16
import json
import os
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from Crypto.Hash import HMAC, SHA512


def get_secrets(data: bytes, order: list[int]) -> list[bytes]:
    secrets = []
    cur = 0
    if sum(order) != len(data):
        raise ValueError("Order does not match data length")
    for i in order:
        secrets.append(data[cur:cur+i])
    return secrets
        


def protect_firmware(infile: str, outfile: str, version: int, message: str,secret_file: str):
    # Load firmware binary from infile
    with open(infile, mode="rb") as fp:
        firmware = fp.read()
    
    # Read secrets as a json file
    with open(secrets, mode="rb") as fp:
        ed25519_private_key, hmac_key, aes_key  = get_secrets(fp.read(),[32,32,32])

    # Pack version and size into two little-endian shorts
    metadata = p16(version, endian='little') + p16(len(firmware), endian='little')  

    # Combine parts into single firmware blob
    firmware_blob = metadata + firmware + message.encode() + b"\x00"
    
    ed25519_private_key = ECC.import_key(ed25519_private_key)
    signer = eddsa.new(ed25519_private_key,mode='rfc8032')
    signature = signer.sign(firmware_blob)
    signed_firmware_blob = firmware_blob + signature
    
    hmac = HMAC.new(hmac_key, digestmod=SHA512)
    hmac.update(signed_firmware_blob)
    hmac_digest = hmac.digest()
    
    signed_hashed_firmware_blob = signed_firmware_blob + hmac_digest
    
    aes_nonce = os.urandom(16)
    
    aes = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)
    aes_ciphertext, aes_tag = aes.encrypt_and_digest(signed_hashed_firmware_blob)
    
    final_firmware_blob = aes_nonce + aes_ciphertext + aes_tag

    # Write firmware blob to outfile
    with open(outfile, mode="wb+") as outfile:
        outfile.write(final_firmware_blob)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=False,default="firmware.bin")
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=False,default="protected_firmware.bin")
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    parser.add_argument("--secrets", help="Path to the secrets json file.", required=False, default="secrets_build.bin")
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message,secret_file=args.secrets)
