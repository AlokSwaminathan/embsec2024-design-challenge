#include "firmware.h"

#include <aes.h>
#include <eeprom.h>
#include <wolfssl/wolfcrypt/ed25519.h>

#include "bootloader.h"
#include "secret_keys.h"

// Variables
// Firmware Buffer
unsigned char data[FLASH_PAGESIZE];
uint16_t *fw_version_address;
uint16_t *fw_size_address;
uint8_t *fw_release_message_address;
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

  uint32_t calc_crc = 0;
  uint32_t recv_crc = 0;

  /* Loop here until you can get all your characters and stuff */
  while (1) {
    // Get two bytes for the length.
    rcv = uart_read(UART0, BLOCKING, &read);
    frame_length = (int)rcv;
    rcv = uart_read(UART0, BLOCKING, &read);
    frame_length += ((int)rcv << 8);

    if (frame_length == 0) {
      uart_write(UART0, DONE);
      while (UARTBusy(UART0_BASE)) {
      };
      break;
    }

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
      ((uint8_t *)&recv_crc)[i] = uart_read(UART0, BLOCKING, &read);
    }

    // Validate recv_crc to ensure data integrity over UART
    if (recv_crc != calc_crc) {
      uart_write(UART0, RESEND);
      while (UARTBusy(UART0_BASE)) {
      };
      // Request a resend
      data_index -= frame_length;  // Remove the frame from the buffer
      if (data_index < 0) {
        data_index = 0;
      }
      total_length -= frame_length;
      continue;
    }

    uart_write(UART0, OK);
    // Acknowledge that frame was successfully received
    while (UARTBusy(UART0_BASE)) {
    };
  }
  // Program leftover frame data to flash
  if (data_index > 0) {
    int32_t res = program_flash((void *)page_addr, data, data_index);
    if (res != 0) {
      uart_write(UART0, ERROR);
      while (UARTBusy(UART0_BASE)) {
      };
      SysCtlReset();
    }
  }

  // TODO : Decrypt the firmware in flash
  decrypt_firmware(total_length);
  verify_firmware(total_length);
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
      "LDR R0,=0x20005\n\t"
      "BX R0\n\t");
}

void decrypt_firmware(uint32_t encrypted_firmware_size) {
  uint8_t aes_key[AES_KEY_SIZE];

  // Encrypted firmware has IV prepended
  uint32_t iv[AES_IV_SIZE];
  uint32_t firmware_size = encrypted_firmware_size - AES_IV_SIZE;

  // Read the AES key from EEPROM
  EEPROMRead((uint32_t*)aes_key, 0x00, AES_KEY_SIZE);

  // Enable the CCM module and wait for it to be ready
  SysCtlPeripheralEnable(SYSCTL_PERIPH_CCM0);
  while (!SysCtlPeripheralReady(SYSCTL_PERIPH_CCM0));

  // Reset the AES module
  AESReset(AES_BASE);

  // Configure the AES module for decryption in CBC mode with 256-bit key
  AESConfigSet(AES_BASE, AES_CFG_DIR_DECRYPT | AES_CFG_MODE_CBC | AES_CFG_KEY_SIZE_256BIT);

  // Set the decryption key
  AESKey1Set(AES_BASE, (uint32_t*)aes_key, AES_CFG_KEY_SIZE_256BIT);

  // Decrypt the data in 1kB chunks
  uint8_t *block_addr = (uint8_t*)FW_BASE;
  for (int i = 0; i < firmware_size/BLOCK_SIZE; i += BLOCK_SIZE) {
    // Clone in IV from flash since flash will be overwritten
    memcpy(iv, block_addr, AES_IV_SIZE);

    // Set the initial value of IV
    AESIVSet(AES_BASE, iv);

    // Decrypt the firmware
    if (!AESDataProcess(AES_BASE, (uint32_t*)(block_addr+16), (uint32_t*)data, BLOCK_SIZE)) {
      SysCtlReset();
    }

    // Write the decrypted firmware back to flash
    if (program_flash((void *)block_addr, data, BLOCK_SIZE) != 0) {
      SysCtlReset();
    }
    block_addr += BLOCK_SIZE;
  }

  // Decrypt last, incomplete block
  uint32_t last_block_size = firmware_size % BLOCK_SIZE;
  if (last_block_size > 0) {
    // Clone in IV from flash since flash will be overwritten
    memcpy(iv, block_addr, AES_IV_SIZE);

    // Set the initial value of IV
    AESIVSet(AES_BASE, iv);

    // Decrypt the firmware
    if (!AESDataProcess(AES_BASE, (uint32_t*)(block_addr+16), (uint32_t*)data, last_block_size)) {
      SysCtlReset();
    }

    // Write the decrypted firmware back to flash
    if (program_flash((void *)block_addr, data, last_block_size) != 0) {
      SysCtlReset();
    }
  }

  // Delete AES key from memory
  memset(aes_key, 0xFF, AES_KEY_SIZE);
}

void verify_firmware(uint32_t encrypted_firmware_size) {
  // Initialize ed25519 key and public key
  ed25519_key ed25519_key;
  uint8_t ed25519_public_key[ED25519_PUBLIC_KEY_SIZE];
  uint8_t *signature = (uint8_t*)(FW_BASE + encrypted_firmware_size - ED25519_SIG_SIZE);

  // Read the ED25519 public key from EEPROM
  EEPROMRead((uint32_t*)ed25519_public_key, AES_KEY_SIZE, ED25519_PUBLIC_KEY_SIZE);

  // Initialize ED25519 public key
  if (wc_ed25519_init(&ed25519_key) != 0) {
    SysCtlReset();
  }
  if (wc_ed25519_import_public((byte *)ed25519_public_key, ED25519_PUBLIC_KEY_SIZE, &ed25519_key) != 0) {
    SysCtlReset();
  }

  // Verify signature
  int verified;
  int ret = wc_ed25519_verify_msg(signature, ED25519_SIG_SIZE, (byte*)FW_BASE, encrypted_firmware_size-ED25519_SIG_SIZE,
                                 &verified, &ed25519_key);
  if (ret != 0 || verified != 1) {
    SysCtlReset();
  }

  // Free ED25519 key
  wc_ed25519_free(&ed25519_key);

  // Delete ED25519 public key from memory
  memset(ed25519_public_key, 0xFF, ED25519_PUBLIC_KEY_SIZE);
}
