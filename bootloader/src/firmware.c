#include "firmware.h"

#include <aes.h>
#include <eeprom.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ed25519.h>

#include "bootloader.h"
#include "secret_keys.h"

// Variables
// Firmware Buffer
unsigned char data[FLASH_PAGESIZE];
// Padding amount for firmware
uint8_t firmware_padding_size;

/*
 * Load the firmware into flash.
 */
uint32_t load_firmware(void) {
  int frame_length = 0;
  int read = 0;
  uint32_t rcv = 0;
  uint32_t total_length = 0;

  uint32_t data_index = 0;
  uint32_t page_addr = FW_TEMP_BASE;

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
        if (page_addr - FW_TEMP_BASE >= MAX_CHUNK_NO * FLASH_PAGESIZE) {
          uart_write(UART0, ERROR);
          while (UARTBusy(UART0_BASE)) {
          };
          SysCtlReset();
        }
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

  return total_length;
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
    while (UARTBusy(UART0_BASE)) {
    };
    SysCtlReset();  // Reset device
    return;
  }

  // Write the firmware version
  uart_write_str(UART0, "Firmware version: ");
  if (!__FW_IS_DEBUG) {
    uart_write_unsigned_short(UART0, *(uint16_t *)FW_VERSION_ADDR);
  } else {
    uart_write_str(UART0, "0");
  }
  nl(UART0);

  // Write the firmware release message
  uart_write_str(UART0, (char *)FW_RELEASE_MESSAGE_ADDR);
  nl(UART0);

  while (UARTBusy(UART0_BASE)) {
  };

  // Boot the firmware
  __asm(
      "LDR R0,=0x20001\n\t"
      "BX R0\n\t");
}

void decrypt_firmware(uint32_t encrypted_firmware_size) {
  uint8_t aes_key[AES_KEY_SIZE];
  uint32_t firmware_size = encrypted_firmware_size - AES_IV_SIZE;
  Aes aes_cbc;

  // Read the AES key from EEPROM
  EEPROMRead((uint32_t *)aes_key, AES_KEY_EEPROM_ADDR, AES_KEY_SIZE);

  // Initalize the AES module
  wc_AesInit(&aes_cbc, NULL, INVALID_DEVID);

  // Set the AES key
  wc_AesSetKey(&aes_cbc, aes_key, AES_KEY_SIZE, (byte *)FW_TEMP_BASE, AES_DECRYPTION);

  // Decrypt the data in 1kB chunks
  uint8_t *block_addr = (uint8_t *)FW_TEMP_BASE;
  for (int i = 0; i < firmware_size / BLOCK_SIZE; i++) {
    // Set the initial value of IV
    wc_AesSetIV(&aes_cbc, block_addr);

    // Decrypt the firmware
    if (wc_AesCbcDecrypt(&aes_cbc, data, (byte *)((uint32_t)block_addr + AES_IV_SIZE), BLOCK_SIZE) != 0) {
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
    // Set the initial value of IV
    wc_AesSetIV(&aes_cbc, block_addr);

    // Decrypt the firmware
    if (wc_AesCbcDecrypt(&aes_cbc, data, (byte *)((uint32_t)block_addr + AES_IV_SIZE), last_block_size) != 0) {
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
  // Remove IV size
  encrypted_firmware_size -= AES_IV_SIZE;

  // Initialize ed25519 key and public key
  ed25519_key ed25519_key;
  uint8_t ed25519_public_key[ED25519_PUBLIC_KEY_SIZE];

  // Find true signature behind padding
  uint8_t *signature = (uint8_t *)(FW_TEMP_BASE + encrypted_firmware_size);
  firmware_padding_size = *(signature - 1);
  encrypted_firmware_size -= firmware_padding_size;
  signature -= firmware_padding_size;
  signature -= ED25519_SIG_SIZE;

  // Read the ED25519 public key from EEPROM
  EEPROMRead((uint32_t *)ed25519_public_key,ED25519_PUBLIC_KEY_EEPROM_ADDR, ED25519_PUBLIC_KEY_SIZE);

  // Initialize ED25519 public key
  if (wc_ed25519_init(&ed25519_key) != 0) {
    SysCtlReset();
  }
  if (wc_ed25519_import_public((byte *)ed25519_public_key, ED25519_PUBLIC_KEY_SIZE, &ed25519_key) != 0) {
    SysCtlReset();
  }

  // Verify signature
  int verified;
  int ret = wc_ed25519_verify_msg(signature, ED25519_SIG_SIZE, (byte *)FW_TEMP_BASE, encrypted_firmware_size - ED25519_SIG_SIZE,
                                  &verified, &ed25519_key);
  if (ret != 0 || verified != 1) {
    SysCtlReset();
  }

  // Free ED25519 key
  wc_ed25519_free(&ed25519_key);

  // Delete ED25519 public key from memory
  memset(ed25519_public_key, 0xFF, ED25519_PUBLIC_KEY_SIZE);
}

// Sets the firmware metadata to the appropriate addresses and variables
// This should only be called after the firmware is loaded, decrypted, and verified, the version number has been checked, and the firmware has been finalized
void set_firmware_metadata(uint32_t encrypted_firmware_size) {
  uint16_t version = *(uint16_t *)(FW_TEMP_BASE);
  uint16_t size = *(uint16_t *)(FW_TEMP_BASE + VERSION_LEN);
  uint8_t *fw_release_message_address = (uint8_t *)(FW_TEMP_BASE + INITIAL_METADATA_LEN + size);
  uint32_t fw_release_message_size = encrypted_firmware_size - firmware_padding_size - size - 4;
  if (fw_release_message_size > MAX_MSG_LEN) {
    fw_release_message_size = MAX_MSG_LEN;
  }

  bool is_debug = (version == 0);

  if (is_debug) {
    memcpy(data, (uint8_t *)FW_VERSION_ADDR, VERSION_LEN);
    data[1023] = DEBUG_BYTE;
  } else {
    memcpy(data, (uint8_t *)FW_TEMP_BASE, VERSION_LEN);
    data[1023] = DEFAULT_BYTE;
  }
  memcpy(data + VERSION_LEN, fw_release_message_address, fw_release_message_size);

  // Write the metadata to permanent location in flash
  program_flash((void *)FW_VERSION_ADDR, data, FLASH_PAGESIZE);
}

// Check the firmware version to see if it is >= the last version
// If it is 0 just let it go through
// If it is less than the last version, reset the device
void check_firmware_version(void) {
  uint16_t ver = *(uint16_t *)FW_TEMP_BASE;
  uint16_t last_ver = *(uint16_t *)FW_VERSION_ADDR;

  if (ver == 0 || ver >= last_ver) {
    return;
  } else if (ver < last_ver) {
    SysCtlReset();
  }
}

// Take the firmware and write it to the final firmware location in flash where it will be booted from
// This should only be called after the firmware is loaded, decrypted, and verified, and the version number has been checked
void finalize_firmware(void) {
  uint32_t firmware_size = (uint32_t)(*(uint16_t *)(FW_TEMP_BASE + 2));

  uint32_t blocks = firmware_size / FLASH_PAGESIZE;
  if (firmware_size % FLASH_PAGESIZE != 0) {
    blocks++;
  }
  for (uint32_t i = 0; i < blocks; i++) {
    program_flash((void *)(FW_BASE + i * FLASH_PAGESIZE), (uint8_t *)(FW_TEMP_BASE + 4 + i * FLASH_PAGESIZE), FLASH_PAGESIZE);
  }
}
