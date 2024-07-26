#include "firmware.h"

#include <aes.h>
#include <eeprom.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ed25519.h>

#include "bootloader.h"
#include "secret_keys.h"

// Firmware Buffer
unsigned char data[FLASH_PAGESIZE];

// Size of encrypted firmware
uint32_t encrypted_fw_size;

// Load firmware from flash
// Recieves it in frames with size, data, checksum
void load_firmware(void) {
  int frame_length = 0;
  int read = 0;
  uint32_t rcv = 0;
  uint32_t total_length = 0;

  uint32_t data_index = 0;
  uint32_t page_addr = FW_TEMP_BASE;

  uint32_t calc_crc = 0;
  uint32_t recv_crc = 0;

  // Read frame till a 0 length
  while (1) {
    // Get two bytes for the length.
    rcv = uart_read(UART0, BLOCKING, &read);
    frame_length = (int)rcv;
    rcv = uart_read(UART0, BLOCKING, &read);
    frame_length += ((int)rcv << 8);

    // finish if there is nothing left to load in
    if (frame_length == 0) {
      break;
    }

    // quit if frame length is more than the page size so there is no chance of multiple flash programs in one frame
    if (frame_length > FLASH_PAGESIZE) {
      error(UART0, "Frame length cannot be more than the flash pagesize (1024)\n");
    }

    // initialization for checksum
    calc_crc = 0xFFFFFFFF;

    // Get the number of bytes specified
    for (int i = 0; i < frame_length; i++) {
      if (data_index >= FLASH_PAGESIZE) {
        if (page_addr - FW_TEMP_BASE >= MAX_CHUNK_NO * FLASH_PAGESIZE) {
          error(UART0, "Protected firmware should be more than 32kb in size\n");
        }
        int32_t res = program_flash((void *)page_addr, data, data_index);
        if (res != 0) {
          error(UART0, "Failed to program data to flash\n");
        }

        // go to next page of flash memory
        page_addr += FLASH_PAGESIZE;
        data_index = 0;
      }

      // Read byte
      data[data_index] = uart_read(UART0, BLOCKING, &read);

      // Dynamically calculate crc
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

    // Acknowledge that frame was successfully received
    uart_write(UART0, OK);
    while (UARTBusy(UART0_BASE)) {
    };
  }

  // Program leftover frame data to flash
  if (data_index > 0) {
    int32_t res = program_flash((void *)page_addr, data, data_index);
    if (res != 0) {
      error(UART0, "Failed to program data to flash\n");
    }
  }

  encrypted_fw_size = total_length;
}

// Boots the firmware stored in FW_BASE
// Verifies it against the signature at FW_SIG_ADDR
void boot_firmware(void) {
  // Check if firmware loaded
  int fw_present = 0;
  for (uint8_t *i = (uint8_t *)FW_BASE; i < (uint8_t *)FW_BASE + 20; i++) {
    if (*i != 0xFF) {
      fw_present = 1;
    }
  }

  // if no firmware, quit
  if (!fw_present) {
    boot_error(UART0, "No firmware loaded.\n");
  }

  // Verify the firmware before booting
  bool verified = pre_boot_verify_firmware();
  if (!verified) {
    boot_error(UART0, "Firmware verification failed.\n");
  }

  // Write the firmware version
  uart_write_str(UART0, "Firmware version: ");
  if (!__FW_IS_DEBUG) {
    uart_write_unsigned_short(UART0, *(uint16_t *)FW_VERSION_ADDR);
  } else {
    uart_write_str(UART0, "0 (DEBUG MODE)");
  }
  nl(UART0);

  // Write the firmware release message
  uart_write_str(UART0, (char *)FW_RELEASE_MSG_ADDR);
  nl(UART0);

  while (UARTBusy(UART0_BASE)) {
  };

  // hides the key so it cannot be accessed until board reboot
  EEPROMBlockHide(AES_KEY_EEPROM_ADDR / EEPROM_BLOCK_SIZE);

  // Boot the firmware, permanently leaves bootloader execution context until reboot
  __asm(
      "LDR R0,=0x20001\n\t"
      "BX R0\n\t");
}

// Decrypt the firmware in place using the AES key
void decrypt_firmware() {
  uint8_t aes_key[AES_KEY_SIZE];
  uint32_t firmware_size = encrypted_fw_size - AES_IV_SIZE;
  Aes aes_cbc;

  // Read the AES key from EEPROM
  EEPROMRead((uint32_t *)aes_key, AES_KEY_EEPROM_ADDR, AES_KEY_SIZE);
  EEPROMBlockHide(AES_KEY_EEPROM_ADDR / EEPROM_BLOCK_SIZE);

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
      error(UART0, "Failed to decrypt firmware\n");
    }

    // Write the decrypted firmware back to flash
    if (program_flash((void *)block_addr, data, BLOCK_SIZE) != 0) {
      error(UART0, "Failed to write decrypted firmware to flash\n");
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
      error(UART0, "Failed to decrypt firmware\n");
    }

    // Write the decrypted firmware back to flash
    if (program_flash((void *)block_addr, data, last_block_size) != 0) {
      error(UART0, "Failed to write decrypted firmware to flash\n");
    }
  }

  // Delete AES key from memory
  memset(aes_key, 0xFF, AES_KEY_SIZE);
}

// Verify the firmware using the ed25519 public key
// This ensures integrity and authenticity
void verify_firmware() {
  // Remove IV size
  encrypted_fw_size -= AES_IV_SIZE;

  // Initialize ed25519 key and public key
  ed25519_key ed25519_key;
  uint8_t ed25519_public_key[ED25519_PUBLIC_KEY_SIZE];

  // Find true signature behind padding
  uint8_t *signature = (uint8_t *)(FW_TEMP_BASE + encrypted_fw_size);
  uint8_t fw_padding_size = *(signature - 1);
  encrypted_fw_size -= fw_padding_size;
  signature -= fw_padding_size;
  signature -= ED25519_SIG_SIZE;

  // Read the ED25519 public key from EEPROM
  EEPROMRead((uint32_t *)ed25519_public_key, ED25519_PUBLIC_KEY_EEPROM_ADDR, ED25519_PUBLIC_KEY_SIZE);

  // Initialize ED25519 public key
  if (wc_ed25519_init(&ed25519_key) != 0) {
    error(UART0, "Failed to initialize ed25519 key\n");
  }
  if (wc_ed25519_import_public((byte *)ed25519_public_key, ED25519_PUBLIC_KEY_SIZE, &ed25519_key) != 0) {
    error(UART0, "Failed to import ed25519 public key\n");
  }

  // Verify signature
  int verified;
  int ret = wc_ed25519ph_verify_msg(signature, ED25519_SIG_SIZE, (byte *)FW_TEMP_BASE, encrypted_fw_size - ED25519_SIG_SIZE, &verified, &ed25519_key, NULL, 0);
  if (ret != 0 || verified != 1) {
    error(UART0, "Verification of ed25519 signature failed\n");
  }

  // Free ED25519 key
  wc_ed25519_free(&ed25519_key);

  // Delete ED25519 public key from memory
  memset(ed25519_public_key, 0xFF, ED25519_PUBLIC_KEY_SIZE);
}

// Sets the firmware metadata to the appropriate addresses and variables
// This should only be called after the firmware is loaded, decrypted, and verified, the version number has been checked, and the firmware has been finalized
void set_firmware_metadata() {
  uint16_t version = *(uint16_t *)(FW_TEMP_VERSION_ADDR);
  uint16_t size = *(uint16_t *)(FW_TEMP_SIZE_ADDR);

  // If the release message size is greater than the MAX_MSG_LEN or is corrupted somehow, reset so unintentional memory won't be printed
  uint32_t fw_release_message_size = 1;
  for (uint8_t *addr = (uint8_t *)FW_TEMP_RELEASE_MSG_ADDR; *addr != '\0'; addr++, fw_release_message_size++) {
    if (fw_release_message_size >= MAX_MSG_LEN) {
      error(UART0, "Firmware release message is too large, max size is 255 bytes\n");
    }
  }

  uint8_t *sig = (uint8_t *)(FW_TEMP_BASE + INITIAL_METADATA_LEN + fw_release_message_size + size);

  bool is_debug = (version == 0);

  // Clear all old values from data so they aren't written to flash
  memset(data, 0xFF, sizeof(data));

  // Don't write a new version if debug mode
  if (is_debug) {
    memcpy(data, (uint8_t *)FW_VERSION_ADDR, FW_VERSION_LEN);
    data[FLASH_PAGESIZE - 1] = DEBUG_BYTE;
  } else {
    memcpy(data, (uint8_t *)FW_TEMP_BASE, FW_VERSION_LEN);
    data[FLASH_PAGESIZE - 1] = DEFAULT_BYTE;
  }

  // Copy rest of metadata to data
  memcpy(data + FW_VERSION_LEN, (uint8_t *)FW_TEMP_SIZE_ADDR, FW_SIZE_LEN);
  memcpy(data + INITIAL_METADATA_LEN, (uint8_t *)FW_TEMP_RELEASE_MSG_ADDR, fw_release_message_size);
  memcpy(data + (FW_SIG_ADDR - FW_VERSION_ADDR), sig, FW_SIG_LEN);

  // Write the metadata to permanent location in flash
  if (program_flash((void *)FW_METADATA_BASE, data, FLASH_PAGESIZE) != 0) {
    error(UART0, "Failed to write firmware metadata to permanent location in flash\n");
  }
}

// Check the firmware version to see if it is >= the last version
// If it is 0 just let it go through
// If it is less than the last version, reset the device
void check_firmware_version(void) {
  uint16_t ver = *(uint16_t *)FW_TEMP_VERSION_ADDR;
  uint16_t last_ver = *(uint16_t *)FW_VERSION_ADDR;

  if (ver == 0 || ver >= last_ver) {
    return;
  } else if (ver < last_ver) {
    error(UART0, "Firmware version is too old\n");
  }
}

// Take the firmware and write it to the final firmware location in flash where it will be booted from
// This should only be called after the firmware is loaded, decrypted, and verified, and the version number has been checked
void finalize_firmware(void) {
  uint32_t firmware_size = (uint32_t)(*(uint16_t *)FW_TEMP_SIZE_ADDR);

  // Calculate number of blocks to write and add an extra one if firmware isn't multiple of 1024
  uint32_t blocks = firmware_size / FLASH_PAGESIZE;
  if (firmware_size % FLASH_PAGESIZE != 0) {
    blocks++;
  }

  int ret = 0;
  for (uint32_t i = 0; i < blocks; i++) {
    ret += program_flash((void *)(FW_BASE + i * FLASH_PAGESIZE), (uint8_t *)(FW_TEMP_BASE + 4 + i * FLASH_PAGESIZE), FLASH_PAGESIZE);
  }

  // If the firmware was not properly moved to its bootable location then delete it all and quit
  // If you don't delete there will be corrupt firmware
  if (ret != 0) {
    for (uint32_t i = 0; i < blocks; i++) {
      FlashErase(FW_BASE + i * FLASH_PAGESIZE);
    }
    error(UART0, "Failed to copy firmware to proper location in memory");
  }
}

// Verify the firmware before booting
// Dynamically computes the SHA512 Hash of metadata+firmware+release_message
// Verifies that with the stored signature
bool pre_boot_verify_firmware(void) {
  wc_Sha512 sha512;
  uint8_t hash[SHA512_DIGEST_SIZE];

  // Initialize SHA512
  if (wc_InitSha512(&sha512) != 0) {
    boot_error(UART0, "Failed to initialize SHA512 struct\n");
  }

  int ret = 0;

  // Start hash with metadata
  uint16_t ver = __FW_IS_DEBUG ? 0 : *(uint16_t *)FW_VERSION_ADDR;
  uint16_t size = *(uint16_t *)FW_SIZE_ADDR;
  ret |= wc_Sha512Update(&sha512, (uint8_t *)&ver, FW_VERSION_LEN);
  ret |= wc_Sha512Update(&sha512, (uint8_t *)&size, FW_SIZE_LEN);

  // Add firmware to hash
  ret |= wc_Sha512Update(&sha512, (byte *)FW_BASE, size);

  // Add release message to hash
  uint16_t msg_size = 1;
  for (uint8_t *c = (uint8_t *)FW_RELEASE_MSG_ADDR; *c != '\0'; c++) {
    msg_size++;
  }
  ret |= wc_Sha512Update(&sha512, (byte *)FW_RELEASE_MSG_ADDR, msg_size);

  ret |= wc_Sha512Final(&sha512, hash);

  // If any SHA operations failed, then reset
  if (ret != 0) {
    boot_error(UART0, "Failed to calculate SHA512 hash\n");
  }

  // Verify signature
  ed25519_key ed25519_key;
  uint8_t ed25519_public_key[ED25519_PUBLIC_KEY_SIZE];

  EEPROMRead((uint32_t *)ed25519_public_key, ED25519_PUBLIC_KEY_EEPROM_ADDR, ED25519_PUBLIC_KEY_SIZE);

  if (wc_ed25519_init(&ed25519_key) != 0) {
    boot_error(UART0, "Failed to init ed25519 key\n");
  }
  if (wc_ed25519_import_public((byte *)ed25519_public_key, ED25519_PUBLIC_KEY_SIZE, &ed25519_key) != 0) {
    boot_error(UART0, "Failed to import ed25519 public key\n");
  }

  int verified;
  ret = wc_ed25519ph_verify_hash((uint8_t *)FW_SIG_ADDR, ED25519_SIG_SIZE, hash, sizeof(hash), &verified, &ed25519_key, NULL, 0);

  // Free the key
  wc_ed25519_free(&ed25519_key);

  if (ret != 0 || verified != 1) {
    return false;
  } else {
    return true;
  }
}
