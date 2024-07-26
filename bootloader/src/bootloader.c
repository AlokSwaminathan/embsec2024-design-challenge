// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

#include "bootloader.h"

#include "firmware.h"
#include "secret_keys.h"
#include "secrets.h"
#include "util.h"

#include "driverlib/eeprom.h"

// Stores secrets then just loops while getting input for booting or updating
int main(void) {
  write_and_remove_secrets();

  initialize_uarts();

  uart_write_str(UART0, "Welcome to the BWSI Vehicle Update Service!\n");
  uart_write_str(UART0, "Send \"U\" to update, and \"B\" to run the firmware.\n");

  int resp;

  // Constantly query user for response
  // if 'B', boot the existing loaded firmware
  // if 'U', cooperate with fw_update to update the current firmware
  while (1) {
    uint32_t instruction = uart_read(UART0, BLOCKING, &resp);

    if (instruction == UPDATE) {
      uart_write_str(UART0, "U");
      while (UARTBusy(UART0_BASE)) {
      };
      load_firmware();
      decrypt_firmware();
      verify_firmware(); 
      check_firmware_version();
      set_firmware_metadata();
      finalize_firmware();
      uart_write(UART0,DONE);
      uart_write_str(UART0, "Loaded new firmware.\n");
      nl(UART0);
      while (UARTBusy(UART0_BASE)) {
      };
    } else if (instruction == BOOT) {
      uart_write_str(UART0, "B");
      uart_write_str(UART0, "Booting firmware...\n");
      while (UARTBusy(UART0_BASE)) {
      };
      boot_firmware();
    }
  }
}

