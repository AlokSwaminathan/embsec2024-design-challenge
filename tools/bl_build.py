#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Bootloader Build Tool

This tool is responsible for building the bootloader from source and copying
the build outputs into the host tools directory for programming.
"""
import os
import pathlib
import subprocess
import json
from Crypto.PublicKey import ECC
import base64

REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")


def make_bootloader(ed25519_pub_key, aes_key, hmac_key) -> bool:
    # Build the bootloader from source.

    os.chdir(BOOTLOADER_DIR)

    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")

    # Return True if make returned 0, otherwise return False.
    return status == 0

def save_to_secrets(ed25519_private_key, aes_key, hmac_key):
    json_data = {
        "ed25519_private_key": base64.b64encode(ed25519_private_key).decode('utf-8'),
        "aes_key": base64.b64encode(aes_key).decode('utf-8'),
        "hmac_key": base64.b64encode(hmac_key).decode('utf-8')
    }
    os.chdir(BOOTLOADER_DIR)
    with open("secret_build_outputs.txt", "w") as f:
        json.dumps(json_data, f,indent=4)

if __name__ == "__main__":
    ed25519_key = ECC.generate(curve='ed25519')
    ed25519_private_key = ed25519_key.export_key(format='PEM')
    ed25519_public_key = ed25519_key.public_key().export_key(format='PEM')
    aes_key = os.urandom(32)
    hmac_key = os.urandom(32)
    if make_bootloader(ed25519_public_key,aes_key,hmac_key):
        save_to_secrets(ed25519_private_key,aes_key,hmac_key)
    else:
        print("Failed to build bootloader.")
        exit(1)