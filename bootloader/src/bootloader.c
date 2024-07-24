// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

#include "bootloader.h"

#include "firmware.h"
#include "secret_keys.h"
#include "secrets.h"

#include "driverlib/eeprom.h"

// Forward Declarations
void load_firmware(void);
void boot_firmware(void);
void uart_write_hex_bytes(uint8_t, uint8_t *, uint32_t);

extern uint8_t *fw_release_message_address;

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
  write_and_remove_secrets();

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