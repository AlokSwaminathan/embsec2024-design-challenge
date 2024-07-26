# Cryptographic Automotive Software Handler and Bootloader (CrASHBoot)

Installation and development guide for the most secure (TM) automotive bootloader on the planet! We guarentee that cars running our software will be unhackable (provided hacking is not attempted). Of all the automotive bootloaders, this is certainly one of them. Read on and tremble at our embedded security skillz.

### Overview



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
|   ├── fw_decrypt.py
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
