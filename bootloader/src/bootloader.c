// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

#include "bootloader.h"

#include "secrets.h"

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
#include "uart/uart.h"

// Cryptography Imports
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/sha.h"

// EEPROM Imports
#include "driverlib/eeprom.h"

// Checksum Imports
#include "driverlib/sw_crc.h"

// Forward Declarations
void load_firmware(void);
void boot_firmware(void);
void uart_write_hex_bytes(uint8_t, uint8_t *, uint32_t);
void write_secrets(void);

// Firmware Constants
#define METADATA_BASE 0xFC00  // base address of version and firmware size in Flash
#define FW_BASE 0x10000       // base address of firmware in Flash

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// Protocol Constants
#define OK ((unsigned char)0x00)
#define RESEND ((unsigned char)0x01)
#define DONE ((unsigned char)0x02)
#define ERROR ((unsigned char)0x03)

#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')

// Device metadata
uint16_t *fw_version_address = (uint16_t *)METADATA_BASE;
uint16_t *fw_size_address = (uint16_t *)(METADATA_BASE + 2);
uint8_t *fw_release_message_address;

// Firmware Buffer
unsigned char data[FLASH_PAGESIZE];

// Delay to allow time to connect GDB
// green LED as visual indicator of when this function is running
void debug_delay_led() {
  // Enable the GPIO port that is used for the on-board LED.
  SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);

  // Check if the peripheral access is enabled.
  while (!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOF)) {
  }

  // Enable the GPIO pin for the LED (PF3).  Set the direction as output, and
  // enable the GPIO pin for digital function.
  GPIOPinTypeGPIOOutput(GPIO_PORTF_BASE, GPIO_PIN_3);

  // Turn on the green LED
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, GPIO_PIN_3);

  // Wait
  SysCtlDelay(SysCtlClockGet() * 2);

  // Turn off the green LED
  GPIOPinWrite(GPIO_PORTF_BASE, GPIO_PIN_3, 0x0);
}

int main(void) {
  write_secrets();

  // Enable the GPIO port that is used for the on-board LED.
  SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);

  // Check if the peripheral access is enabled.
  while (!SysCtlPeripheralReady(SYSCTL_PERIPH_GPIOF)) {
  }

  // Enable the GPIO pin for the LED (PF3).  Set the direction as output, and
  // enable the GPIO pin for digital function.
  GPIOPinTypeGPIOOutput(GPIO_PORTF_BASE, GPIO_PIN_3);

  // debug_delay_led();

  initialize_uarts();

  uart_write_str(UART0, "Welcome to the BWSI Vehicle Update Service!\n");
  uart_write_str(UART0, "Send \"U\" to update, and \"B\" to run the firmware.\n");

  int resp;
  while (1) {
    uint32_t instruction = uart_read(UART0, BLOCKING, &resp);

    if (instruction == UPDATE) {
      uart_write_str(UART0, "U");
      load_firmware();
      uart_write_str(UART0, "Loaded new firmware.\n");
      nl(UART0);
    } else if (instruction == BOOT) {
      uart_write_str(UART0, "B");
      uart_write_str(UART0, "Booting firmware...\n");
      boot_firmware();
    }
  }
}

/*
 * Write secrets to EEPROM
 */
#pragma GCC push_options
#pragma GCC optimize("O0")
void write_secrets(void) {
  // Enable and wait for EEPROM to be ready
  SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
  while (!SysCtlPeripheralReady(SYSCTL_PERIPH_EEPROM0)) {
  }

  // Unlock the EEPROM
  uint32_t EEPROMInitRes = EEPROMInit();

  if (EEPROMInitRes != EEPROM_INIT_OK) {
    SysCtlReset();
  }

  // Get keys from secrets.h
  uint8_t AES_SECRET[] = AES_KEY;
  uint8_t ED25519_SECRET[] = ED25519_PUBLIC_KEY;

  // Write the secrets to EEPROM
  EEPROMProgram((uint32_t *)AES_SECRET, 0, sizeof(AES_SECRET));
  EEPROMProgram((uint32_t *)ED25519_SECRET, sizeof(AES_SECRET), sizeof(ED25519_SECRET));

  // Find the secrets in flash
  bool matches_aes = false;
  bool matches_ed = false;
  uint8_t* aes_flash_addr;
  uint8_t* ed_flash_addr;
  for (uint8_t* addr = 0; (addr < (uint8_t*)0x3FFFF) && (!matches_aes || !matches_ed); addr++){
    if (!matches_aes && *addr == AES_SECRET[0]){
      matches_aes = true;
      for (uint8_t* i = addr; i < addr + sizeof(AES_SECRET); i++){
        if (*i != AES_SECRET[(int)(i - addr)]){
          matches_aes = false;
          break;
        }
      }
      if (matches_aes){
        aes_flash_addr = addr;
        addr += sizeof(AES_SECRET);
      }
    } else if (!matches_ed && *addr == ED25519_SECRET[0]){
      for (uint8_t* i = addr; i < addr + sizeof(ED25519_SECRET); i++){
        if (*i != ED25519_SECRET[(int)(i - addr)]){
          matches_ed = false;
          break;
        }
      }
      if (matches_ed){
        ed_flash_addr = addr;
        addr += sizeof(ED25519_SECRET);
      }
    }
  }

  // Clear the secrets from the stack
  for (int i = 0; i < sizeof(AES_SECRET); i++) {
    AES_SECRET[i] = 0xFF;
  }
  for (int i = 0; i < sizeof(ED25519_SECRET); i++) {
    ED25519_SECRET[i] = 0xFF;
  }

  // Remove the secrets from flash
  int32_t res;
  res = FlashProgram((uint32_t *) AES_SECRET, (uint32_t) aes_flash_addr, sizeof(AES_SECRET));
  res |= FlashProgram((uint32_t *) ED25519_SECRET, (uint32_t) ed_flash_addr, sizeof(ED25519_SECRET));
  if (res != 0) {
    SysCtlReset();
  }
}
#pragma GCC pop_options

/*
 * Load the firmware into flash.
 */
void load_firmware(void) {
  int frame_length = 0;
  int read = 0;
  uint32_t rcv = 0;
  uint32_t total_length = 0;

  uint32_t data_index = 0;
  uint32_t page_addr = FW_BASE;
  // uint32_t version = 0;
  // uint32_t size = 0;

  uint32_t calc_crc = 0;
  uint32_t recv_crc = 0;

  /* Loop here until you can get all your characters and stuff */
  while (1) {
    // Get two bytes for the length.
    rcv = uart_read(UART0, BLOCKING, &read);
    frame_length = (int)rcv;
    rcv = uart_read(UART0, BLOCKING, &read);
    frame_length += ((int)rcv << 8);

    // //defense against buffer overflow
    // if(frame_length > FLASH_PAGESIZE) {
    //     uart_write(UART0, ERROR);
    //     SysCtlReset();
    // }

    if (frame_length == 0) {
      uart_write(UART0, DONE);
      break;
    }

    // if (frame_length + data_index > FLASH_PAGESIZE) {
    //     int32_t res = program_flash((void *)page_addr, data, data_index);
    //     if (res != 0) {
    //         uart_write(UART0, ERROR);
    //         SysCtlReset();
    //     }
    //     page_addr += FLASH_PAGESIZE;
    //     data_index = 0;
    // }

    calc_crc = 0xFFFFFFFF;

    // Get the number of bytes specified
    for (int i = 0; i < frame_length; i++) {
      if (data_index >= FLASH_PAGESIZE) {
        int32_t res = program_flash((void *)page_addr, data, data_index);
        if (res != 0) {
          uart_write(UART0, ERROR);
          SysCtlReset();
        }
        page_addr += FLASH_PAGESIZE;
        data_index = 0;
      }
      data[data_index] = uart_read(UART0, BLOCKING, &read);
      calc_crc = Crc32(calc_crc, (uint8_t *)(data + data_index), 1);
      data_index++;
      total_length++;
    }

    for (int i = 0; i < 4; i++) {
      // Use fact that integers are little endian on chip to read recv_crc directly as uint32_t
      ((uint8_t *)recv_crc)[i] = uart_read(UART0, BLOCKING, &read);
    }

    // Validate recv_crc to ensure data integrity over UART
    if (recv_crc != calc_crc) {
      uart_write(UART0, RESEND);   // Request a resend
      data_index -= frame_length;  // Remove the frame from the buffer
      total_length -= frame_length;
      continue;
    }

    uart_write(UART0, OK);  // Acknowledge that frame was successfully received
  }
  if (data_index % 1024 != 0) {
    int32_t res = program_flash((void *)page_addr, data, data_index);
    if (res != 0) {
      uart_write(UART0, ERROR);
      SysCtlReset();
    }
  }

  // TODO : Decrypt the firmware in flash
}

/*
 * Program a stream of bytes to the flash.
 * This function takes the starting address of a 1KB page, a pointer to the
 * data to write, and the number of byets to write.
 *
 * This functions performs an erase of the specified flash page before writing
 * the data.
 */
long program_flash(void *page_addr, unsigned char *data, unsigned int data_len) {
  uint32_t word = 0;
  int ret;
  int i;

  // Erase next FLASH page
  FlashErase((uint32_t)page_addr);

  // Clear potentially unused bytes in last word
  // If data not a multiple of 4 (word size), program up to the last word
  // Then create temporary variable to create a full last word
  if (data_len % FLASH_WRITESIZE) {
    // Get number of unused bytes
    int rem = data_len % FLASH_WRITESIZE;
    int num_full_bytes = data_len - rem;

    // Program up to the last word
    ret = FlashProgram((unsigned long *)data, (uint32_t)page_addr, num_full_bytes);
    if (ret != 0) {
      return ret;
    }

    // Create last word variable -- fill unused with 0xFF
    for (i = 0; i < rem; i++) {
      word = (word >> 8) | (data[num_full_bytes + i] << 24);  // Essentially a shift register from MSB->LSB
    }
    for (i = i; i < 4; i++) {
      word = (word >> 8) | 0xFF000000;
    }

    // Program word
    return FlashProgram(&word, (uint32_t)page_addr + num_full_bytes, 4);
  } else {
    // Write full buffer of 4-byte words
    return FlashProgram((unsigned long *)data, (uint32_t)page_addr, data_len);
  }
}

void boot_firmware(void) {
  // Check if firmware loaded
  int fw_present = 0;
  for (uint8_t *i = (uint8_t *)FW_BASE; i < (uint8_t *)FW_BASE + 20; i++) {
    if (*i != 0xFF) {
      fw_present = 1;
    }
  }

  if (!fw_present) {
    uart_write_str(UART0, "No firmware loaded.\n");
    SysCtlReset();  // Reset device
    return;
  }

  // compute the release message address, and then print it
  uint16_t fw_size = *fw_size_address;
  fw_release_message_address = (uint8_t *)(FW_BASE + fw_size);
  uart_write_str(UART0, (char *)fw_release_message_address);

  // Boot the firmware
  __asm(
      "LDR R0,=0x10001\n\t"
      "BX R0\n\t");
}

void uart_write_hex_bytes(uint8_t uart, uint8_t *start, uint32_t len) {
  for (uint8_t *cursor = start; cursor < (start + len); cursor += 1) {
    uint8_t data = *((uint8_t *)cursor);
    uint8_t right_nibble = data & 0xF;
    uint8_t left_nibble = (data >> 4) & 0xF;
    char byte_str[3];
    if (right_nibble > 9) {
      right_nibble += 0x37;
    } else {
      right_nibble += 0x30;
    }
    byte_str[1] = right_nibble;
    if (left_nibble > 9) {
      left_nibble += 0x37;
    } else {
      left_nibble += 0x30;
    }
    byte_str[0] = left_nibble;
    byte_str[2] = '\0';

    uart_write_str(uart, byte_str);
    uart_write_str(uart, " ");
  }
}
