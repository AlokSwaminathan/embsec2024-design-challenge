#!/usr/bin/env python

# Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-25.

"""
Firmware Updater Tool

A frame consists of three sections:
1. Two bytes for the length of the data section (little endian)
2. A data section of length defined in the length section
3. A four byte CRC32 checksum of the data section

[ 0x02 ] [ variable ] [0x04]
--------------------------------
| Length | Data...  | Checksum |
--------------------------------

In our case, the data is from one line of the Intel Hex formated .hex file

We write a frame to the bootloader, then wait for it to respond with an
OK message so we can write the next frame. The OK message in this case is
just a 0
If the bootloader responds with a 1, then we resend the message
If the bootloader responds with a 2, then we are done writing the firmware
If the bootloader responds with a 3, there has been an error and we should stop writing firmware
"""

import argparse
from pwn import *
import time
from serial import Serial
import platform
from crc import Calculator, Configuration

from util import *

if platform.system() == 'Darwin':
    ser = Serial("/dev/tty.usbmodem0E23AD551", 115200)
else:
    ser = Serial("/dev/ttyACM0", 115200)
    
# Define the bootloader response codes
RESP_OK = b"\x00"
RESP_RESEND = b"\x01"
RESP_DONE = b"\x02"
RESP_ERROR = b"\x03"
DEFAULT_FRAME_SIZE = 257
STARTING_BOOT_STR = "Welcome to the BWSI Vehicle Update Service!\nSend \"U\" to update, and \"B\" to run the firmware."

# Define the CRC32 configuration
crc_config = Configuration(
  width=32,
  polynomial=0x04C11DB7,
  init_value=0xFFFFFFFF,
  final_xor_value=0x00000000,
  reverse_input=True,
  reverse_output=True,
)
crc32 = Calculator(crc_config)

# Set up waiting for bootloader be ready when it has to program flash
running_total = 0
FLASH_PAGESIZE = 1024

def send_frame(ser: Serial, frame: bytes, debug = False):
    global running_total
  
    ser.write(p16(len(frame), endian = 'little'))  # Write the frame length
    
    # anticipates when bootloader will write data to flash
    # waits for it to finish so there is no data loss
    if (running_total % FLASH_PAGESIZE == 0 or 
        running_total // FLASH_PAGESIZE != 
        (running_total + len(frame)) // FLASH_PAGESIZE):
      
      end_amt = (running_total+ len(frame)) % FLASH_PAGESIZE
      ser.write(frame[:-end_amt])
      time.sleep(0.1)
      ser.write(frame[-end_amt:])
    else:
      ser.write(frame)
    
    # send the checksum
    checksum: bytes = p32(crc32.checksum(frame), endian = 'little')
    
    print(f"Checksum: {checksum}") if debug else None
    ser.write(checksum)  # Write the frame checksum

    if debug:
        print(f"Frame size: {len(frame)}")
        print(f"Frame: {get_hex(frame)}")

    resp: bytes = ser.read(1)  # Wait for an OK from the bootloader

    # Check if debugging is enabled
    if debug:
        print("Resp: {}".format(ord(resp)))

    # Handle the received response
    if resp == RESP_ERROR:
        raise RuntimeError(
            "ERROR: Bootloader responded with {}".format(repr(resp)))
    elif resp == RESP_RESEND:
        if debug:
            print("Resending frame")
        send_frame(ser, frame, debug=debug)
        return
    running_total += len(frame)

# wait for bootloader to tell the program that it's ready
def ready_bootloader():
    ser.write(b'U')
    print("Waiting for bootloader to enter update mode")
    while ser.read(1).decode('ascii') != 'U':
        print("Got non-U character from bootloader.")
    print("Bootloader is ready to receive firmware.")

# function for actually flashing the firmware onto the board
def update(ser: Serial, infile:str, debug:bool, frame_size:int):
    running_total = 0
    
    # Open serial port. Set baudrate to 115200. Set timeout to 2 seconds.
    with open(infile, "rb") as fp:
        firmware = fp.read()
    
    ready_bootloader()

    # Send firmware in frames
    num_frames = len(firmware) // frame_size
    num_frames -= 1 if len(firmware) % frame_size == 0 else 0
    for i in range(0, len(firmware), frame_size):
        frame = firmware[i:i+frame_size]
        send_frame(ser, frame, debug = debug)
        print(f"Sent frame {i // frame_size} of {num_frames}")
    

    print("Done writing firmware.")

    # Send a zero length payload to tell the bootloader to finish writing it's page.
    ser.write(p16(0x0000, endian = 'little'))
    resp: bytes = ser.read(1)  # Wait for a DONE from the bootloader
    if resp != RESP_DONE:
        resp = ""
        cur = 0
        while True:
          byte = ser.read(1)
          resp += byte.decode('ascii')
          if STARTING_BOOT_STR in resp:
            break
        print("ERROR: Bootloader responded to zero length frame with ERROR.")
        print("Error message is: {}".format(resp[:-len(STARTING_BOOT_STR)]))
        exit(1)
    print(f"Wrote zero length frame (2 bytes) and finished writing firmware")

    return ser
import argparse

if __name__ == "__main__":
    # Create an argument parser for command line arguments
    parser = argparse.ArgumentParser(description = "Firmware Update Tool")

    parser.add_argument(
        "--firmware", help = "Path to firmware image to load.", required = True)
    
    parser.add_argument(
        "--debug", help = "Enable debugging messages.", action = "store_true")
    
    parser.add_argument(
        "--frame-size", help = "Size of each frame to send to the bootloader.", type = int, default = DEFAULT_FRAME_SIZE)
    
    # Parse the command line arguments
    args = parser.parse_args()
    
    if args.frame_size > 1024:
      print("Frame size must be less than 1024")
      ser.close()
      exit(1)

    # Call the update function with the parsed arguments
    update(ser = ser, infile = args.firmware, debug = args.debug, frame_size= args.frame_size)
    
    ser.close()
