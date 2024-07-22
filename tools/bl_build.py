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
    
    # Write the keys to a secret header file.
    with open("inc/secrets.h", "w") as f:
        f.write("#define ED25519_PUBLIC_KEY \"" + ed25519_pub_key + "\"\n")
        f.write("#define AES_KEY \"" + aes_key + "\"\n")
        f.write("#define HMAC_KEY \"" + hmac_key + "\"\n")
        

    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")

    # Reset the secrets header file
    with open("inc/secrets.h", "w") as f:
        f.write("// No secrets for you :)\n")
        f.write("#define ED25519_PUBLIC_KEY \"\"\n")
        f.write("#define AES_KEY \"\"\n")
        f.write("#define HMAC_KEY \"\"\n")

    # Return True if make returned 0, otherwise return False.
    return status == 0

def save_to_secrets(ed25519_private_key, aes_key, hmac_key):
    json_data = {
        "ed25519_private_key": ed25519_private_key,
        "aes_key": aes_key,
        "hmac_key": hmac_key
    }
    os.chdir(os.path.join(BOOTLOADER_DIR,"bin/"))
    with open("secret_build_outputs.json", "w") as f:
        f.write(json.dumps(json_data,indent=4))

if __name__ == "__main__":
    ed25519_key = ECC.generate(curve='ed25519')
    ed25519_private_key = base64.b64encode(ed25519_key.export_key(format='PEM').encode('ascii')).decode('ascii')
    ed25519_public_key = base64.b64encode(ed25519_key.public_key().export_key(format='PEM').encode('ascii')).decode('ascii')
    aes_key = base64.b64encode(os.urandom(32)).decode('ascii')
    hmac_key = base64.b64encode(os.urandom(32)).decode('ascii')
    if make_bootloader(ed25519_public_key,aes_key,hmac_key):
        save_to_secrets(ed25519_private_key,aes_key,hmac_key)
        print("Bootloader built successfully. Secrets saved.")
    else:
        print("Failed to build bootloader.")
        exit(1)