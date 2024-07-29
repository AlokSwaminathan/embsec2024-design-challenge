# Cryptographic Automotive Software Handler and Bootloader (CrASHBoot)

Installation and development guide for the most secure (TM) automotive bootloader on the planet! We guarentee that cars running our software will be unhackable (provided hacking is not attempted). Of all the automotive bootloaders, this is certainly one of them. Read on and tremble at our embedded security skillz.

## Overview

### Tools (Python scripts)

#### Build Process(bl_build.py):

1. Generates random AES 256 key and a random ed25519 key pair
2. Writes the ed25519 public key and AES key to `bootloader/inc/secret_keys.h`
3. Makes the bootloader
4. Deletes the secrets from `bootloader/inc/secret_keys.h`
5. Pads the bootloader with `0xFF` until it is 256kb in size, then set version metadata to 0 so any version can be loaded to start
6. Writes the ed25519 private key and the AES key in JSON format to `secret_build_output.txt`

#### Encryption process(fw_protect.py):

1. Creates a firmware blob that is version + firmware size + firmware + release message
2. Uses ed25519 to sign the SHA512 hash of the firmware blob, then append that signature
3. Encrypts the blob with AES CBC (randomly generated IV)
4. Prepends IV to ciphertext to generate protected_firmware

Plaintext format:

| 0x02 | 0x02 | ... | ... | 0x01 | 0x40|
| --- | --- | --- | --- | --- | -- |
| Version | Size  | Firmware... | Message... | \x00 | Signature |

#### Updating Process (Sender) (fw_update.py)

We sent our data in frames of the format:

| 0x02 | ... | 0x04|
| --- | --- | --- |
| Length | Data...  | Checksum |

A 0 length frame is sent to indicate completion.

After each frame, wait for a response. If `OK` then continue, if `ERROR`, read and print out the error message, then quit.

After the 0 length frame, the program expects a `DONE` and responds the same to `ERROR`.

### Bootloader

#### Flash Layout:

1. 0x00000-0x20000 is for the bootloader
2. 0x20000-0x30000 is where the firmware is booted from (`FW_BASE`)
3. 0x30000-0x3FC00 is where newly sent firmware is stored while it is decrypted and verified (`FW_TEMP_BASE`)
4. 0x3FC00-0x3FFFF is the last page of flash where metadata is permanently stored (`FW_METADATA_BASE`)

#### Permanent Metadata

1. 0x3FC00 - Version Number (uint16_t) (`FW_VERSION_ADDR`)
2. 0x3FC02 - Firmware Size (uint16_t) (`FW_SIZE_ADDR`)
3. 0x3FC04 - Release Message (null terminated) (`FW_RELEASE_MSG_ADDR`)
4. 0x3FF00 - Signature (0x40 bytes) (`FW_SIG_ADDR`)
5. 0x3FFFF (bit 8) - Debug bit (1 for no, 0 for yes) 

#### Secret handling:

1. Checks if secrets in flash have already been deleted or not
    - If they have been then return
2. Initialize EEPROM and write secrets to EEPROM
3. Iterate through flash to find the secrets then erase them
4. Erase the secrets from RAM
5. Reset


#### Firmware reception process

1. Stores the protected firmware sent by `fw_update` at `FW_TEMP_BASE` (Won't recieve more than 32kb)
   - Writes to flash every time 1kb is read and fills the data buffer
2. Decrypts the firmware in place, shifts everything left by 16 bytes (removes IV)
3. Verifies the firmware with the signature
4. Checks the firmware version with the version at `FW_VERSION_ADDR`
5. Writes the metadata to `FW_METADATA_BASE`
6. Moves the firmware binary to `FW_BASE`
   - If there is an error at this stage, it erases `FW_BASE` to ensure the data at `FW_BASE` isn't corrupted

If an error is encountered, the `ERROR` byte and an error message are sent over `UART0` so `fw_update` can recieve it, then the bootloader resets

#### Firmware booting process

1. Checks the memory at `FW_BASE` to see if there is loaded firmware
2. Dynamically computes a SHA512 hash of the firmware blob in the format from `fw_protect`, then verifies its with the signature at `FW_SIG_ADDR`
3. Writes the firmware version and release message over `UART0`
4. Runs ASM that branches to `FW_BASE` and starts executing the firmware

If an error is encountered, the error message is sent over `UART0` so `picocom` can recieve it, then the bootloader resets

# Project Structure
```
├── bootloader *
│   ├── bin
│   │   ├── bootloader.bin
│   ├── src
│   │   ├── bootloader.c
|   |   ├── firmware.c
|   |   ├── secrets.c
|   |   ├── util.c
│   │   ├── startup_gcc.c
│   ├── bootloader.ld
│   ├── Makefile
├── firmware
│   ├── bin
│   │   ├── firmware.bin
│   ├── lib
│   ├── src
├── lib
│   ├── driverlib
│   ├── inc
│   ├── uart
├── tools *
│   ├── bl_build.py
│   ├── fw_protect.py
│   ├── fw_update.py
│   ├── util.py
├── README.md

Directories marked with * are part of the CrASHBoot system
```

## Bootloader

The `bootloader` directory contains source code that is compiled and loaded onto the TM4C microcontroller. The bootloader manages which firmware can be updated to the TM4C. When connected to the fw_update tool, the bootloader checks the version of the new firmware against the internal firmware version before accepting the new firmware along with the integrity of the firmware.

The bootloader will also start the execution of the loaded vehicle firmware.

## Tools

There are three python scripts in the `tools` directory which are used to:

1. Provision the bootloader (`bl_build.py`)
2. Package the firmware (`fw_protect.py`)
3. Update the firmware to a TM4C with a provisioned bootloader (`fw_update.py`)

### bl_build.py

This script calls `make` in the `bootloader` directory.

### fw_protect.py

This script bundles the version and release message with the firmware binary.

### fw_update.py

This script opens a serial channel with the bootloader, then writes the firmware metadata and binary broken into data frames to the bootloader.

# Building and Flashing the Bootloader

1. Enter the `tools` directory and run `bl_build.py`

```
cd ./tools
python bl_build.py
```

2. Flash the bootloader using `lm4flash` tool
   
```
sudo lm4flash ../bootloader/bin/bootloader.bin
```

# Bundling and Updating Firmware

1. Enter the firmware directory and `make` the example firmware.

```
cd ./firmware
make
```

2. Enter the tools directory and run `fw_protect.py`

```
cd ../tools
python fw_protect.py --infile ../firmware/bin/firmware.bin --outfile firmware_protected.bin --version 2 --message "Firmware V2"
```

This creates a firmware bundle called `firmware_protected.bin` in the tools directory.

3. Reset the TM4C by pressig the RESET button

4. Run `fw_update.py`

```
python fw_update.py --firmware ./firmware_protected.bin
```

If the firmware bundle is accepted by the bootloader, the `fw_update.py` tool will report it wrote all frames successfully.

If the firmware bundle is rejected by the bootloader, the script will print out the error and quit.

Additional firmwares can be updated by repeating steps 3 and 4, but only firmware versions higher than the one flashed to the board (or version 0) will be accepted.

# Interacting with the Bootloader

Using the custom `car-serial` script:
```
car-serial
```

FYI: If you don't have `car-serial` it is just a wrapper for `picocom --baud 115200 /dev/tty.usbmodem0E23AD551 --imap lfcrlf`

You can now interact with the bootloader and firmware! Type 'B' to boot.

Exit miniterm: `Ctrl-]`
Exit picocom: `Ctrl-A X`

Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED <br>
Approved for public release. Distribution unlimited 23-02181-25.
