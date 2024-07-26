// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

#ifndef BOOTLOADER_H
#define BOOTLOADER_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

// Import util functions
#include "util.h"
#include "firmware.h"

// Hardware Imports
#include "inc/hw_memmap.h"     // Peripheral Base Addresses
#include "inc/hw_types.h"      // Boolean type
#include "inc/tm4c123gh6pm.h"  // Peripheral Bit Masks and Registers
// #include "inc/hw_ints.h" // Interrupt numbers

// Driver API Imports
#include "driverlib/flash.h"      // FLASH API
#include "driverlib/interrupt.h"  // Interrupt API
#include "driverlib/sysctl.h"     // System control API (clock/reset)

// Application Imports
#include "driverlib/gpio.h"
#include "driverlib/uart.h"
#include "uart/uart.h"

// Cryptography Imports
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/sha.h"

// Checksum Imports
#include "driverlib/sw_crc.h"

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// EEPROM Constants
#define EEPROM_BLOCK_SIZE 0x40
#define AES_KEY_EEPROM_ADDR EEPROM_BLOCK_SIZE
#define ED25519_PUBLIC_KEY_EEPROM_ADDR EEPROM_BLOCK_SIZE*2  

// Protocol Constants
#define OK ((unsigned char)0x00)
#define RESEND ((unsigned char)0x01)
#define DONE ((unsigned char)0x02)
#define ERROR ((unsigned char)0x03)

#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')

// Data buffer sizes
#define IV_LEN 16
#define MAX_MSG_LEN 256
#define SIG_SIZE 256
#define BLOCK_SIZE FLASH_PAGESIZE
#define MAX_CHUNK_NO 32  // 30KB firmware + padding

#endif
