// Copyright 2024 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-25.

#include "bootloader.h"

#include "firmware.h"
#include "secret_keys.h"
#include "secrets.h"
#include "util.h"

#include "driverlib/eeprom.h"

// Forward Declarations
void uart_write_hex_bytes(uint8_t, uint8_t *, uint32_t);

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

  // wait until response given from user
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

