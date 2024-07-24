#include "secrets.h"

#include "bootloader.h"
#include "driverlib/eeprom.h"
#include "secret_keys.h"

/*
 * Write secrets to EEPROM
 */
#pragma GCC push_options
#pragma GCC optimize("O0")
void write_and_remove_secrets(void) {
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
  uint8_t AES_SECRET[AES_KEY_SIZE + 4] = AES_KEY;
  uint8_t ED25519_SECRET[ED25519_PUBLIC_KEY_SIZE + 4] = ED25519_PUBLIC_KEY;

  // Write the secrets to EEPROM
  EEPROMProgram((uint32_t*)AES_SECRET, 0, AES_KEY_SIZE);
  EEPROMProgram((uint32_t*)ED25519_SECRET, AES_KEY_SIZE, ED25519_PUBLIC_KEY_SIZE);

  // Remove secrets from flash and stack
  remove_secret(AES_SECRET, AES_KEY_SIZE);
  remove_secret(ED25519_SECRET, ED25519_PUBLIC_KEY_SIZE);
}
#pragma GCC pop_options

// Remove individual secrets from EEPROM
// Secret should be 4 larger than the size of the secret so it can be word aligned
void remove_secret(uint8_t* secret, uint32_t size) {
  // Find the secret in EEPROM
  bool matches = false;
  uint8_t* flash_addr;
  for (uint8_t* addr = 0; (addr < (uint8_t*)0x3FFFF) && !matches; addr++) {
    if (*addr == secret[0]) {
      matches = true;
      for (uint8_t* i = addr; i < addr + size; i++) {
        if (*i != secret[(int)(i - addr)]) {
          matches = false;
          break;
        }
      }
      if (matches) {
        flash_addr = addr;
        addr += size;
      }
    }
  }

  // Clear the secret from the stack
  for (int i = 0; i < size + 4; i++) {
    secret[i] = 0xFF;
  }

  // Word align the secret
  // If not aligned then pad it with the bytes before and after it in flash
  if ((uint32_t)flash_addr % 4 != 0) {
    uint32_t mod = (uint32_t)flash_addr % 4;
    for (flash_addr; (uint32_t)flash_addr % 4 != 0; flash_addr--) {
      secret[((uint32_t)flash_addr % 4) - 1] = *flash_addr;
    }
    for (int i = 0; i < (4 - mod); i++) {
      secret[size + 3 - i] = flash_addr[size + 3 - i];
    }
    size += 4;
  }

  // Clear the secret from flash
  int32_t res = FlashProgram((uint32_t*)secret, (uint32_t)flash_addr, size);
  if (res != 0) {
    SysCtlReset();
  }
}

uint8_t* read_secrets(void) {
}