/**
 * @file main.c
 * @author Frederich Stine
 * @brief eCTF Car Example Design Implementation
 * @date 2023
 *
 * This source file is part of an example system for MITRE's 2023 Embedded
 * System CTF (eCTF). This code is being provided only for educational purposes
 * for the 2023 MITRE eCTF competition, and may not meet MITRE standards for
 * quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2023 The MITRE Corporation
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "inc/hw_ints.h"
#include "inc/hw_memmap.h"

#include "driverlib/eeprom.h"
#include "driverlib/gpio.h"
#include "driverlib/interrupt.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/timer.h"
//#include "driverlib/rom.h"

//#include "trng.h"

#include "secrets.h"

#include "board_link.h"
#include "feature_list.h"
#include "uart.h"

#include "aead.h"
#include "api.h"
#define MAX_MESSAGE_LENGTH			    16
#define MAX_ASSOCIATED_DATA_LENGTH	16

/*** Structure definitions ***/
// Structure of start_car packet FEATURE_DATA
typedef struct {
  uint8_t car_id[8];
  uint8_t num_active;
  uint8_t features[NUM_FEATURES];
  uint8_t Hash[NUM_FEATURES][32];
} FEATURE_DATA;

/*** Macro Definitions ***/
// Definitions for unlock message location in EEPROM
#define UNLOCK_EEPROM_LOC 0x7C0
#define UNLOCK_EEPROM_SIZE 64

/*** Function definitions ***/
// Core functions - unlockCar and startCar
void unlockCar(void);
void startCar(void);

// Helper functions - sending ack messages
void sendAckSuccess(void);
void sendAckFailure(void);

int memcmp_new(const uint8_t *__s1, const uint8_t *__s2, int n);

// Declare password
const uint8_t pass[16] = PASSWORD;
const uint8_t car_id[8] = CAR_ID;
const uint8_t auth[16] = AUTHENTICATON;
const uint8_t key[16] = KEY;

/*
#define CAR_STATE_PTR 0x3FC00
#define FLASH_DATA_SIZE         \
  (sizeof(FLASH_DATA) % 4 == 0) \
      ? sizeof(FLASH_DATA)      \
      : sizeof(FLASH_DATA) + (4 - (sizeof(FLASH_DATA) % 4))


// Defines a struct for the RNG
typedef struct
{
  uint32_t seed;
  uint32_t rng_value;
} RNG_PACKET;
*/

/**
 * @brief Main function for the car example
 *
 * Initializes the RF module and waits for a successful unlock attempt.
 * If successful prints out the unlock flag.
 */
int main(void) {

  //uint8_t data[16];

  // Ensure EEPROM peripheral is enabled
  SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
  EEPROMInit();

  // Initialize UART peripheral
  uart_init();

  // Initialize board link UART
  setup_board_link();

  while (true) {

    unlockCar();
  }
}

/**
 * @brief Function that handles unlocking of car
 */
void unlockCar(void) {
  unsigned char       msg[MAX_MESSAGE_LENGTH];
  unsigned char		ad[MAX_ASSOCIATED_DATA_LENGTH];
  unsigned char		nonce[CRYPTO_NPUBBYTES];
  unsigned long long  mlen;

  nonce[0] = 0x6E;
  nonce[1] = 0x6F;
  nonce[2] = 0x6E; 
  nonce[3] = 0x63;
  nonce[4] = 0x65;
  nonce[5] = 0x6D;
  nonce[6] = 0x65;
  nonce[7] = 0x70;
  nonce[8] = 0x6C;
  nonce[9] = 0x65;
  nonce[10] = 0x61;
  nonce[11] = 0x73;
  nonce[12] = 0x65;
  nonce[13] = 0x79;
  nonce[14] = 0x61;
  nonce[15] = 0x79;

  // Create a message struct variable for receiving data
  MESSAGE_PACKET message;

  uint8_t buffer[256];
  message.buffer = buffer;

  receive_board_message_by_type(&message, AUTH_MAGIC);

  if (!memcmp_new((char *)(message.buffer), (char *)auth, 16)) {
    message.message_len = 16;
    message.magic = NONCE_MAGIC;
    message.buffer = (uint8_t*)nonce;

    send_board_message(&message);
    

    MESSAGE_PACKET message2;
    message2.buffer = buffer;

    // Receive packet with some error checking
    receive_board_message_by_type(&message2, UNLOCK_MAGIC);
    
    crypto_aead_decrypt(msg, &mlen, NULL, message2.buffer, MAX_MESSAGE_LENGTH + CRYPTO_ABYTES, NULL, MAX_ASSOCIATED_DATA_LENGTH, nonce, key);
    
    // If the data transfer is the password, unlock
    if (memcmp_new(msg, (char *)pass, 16) == 0) {
      uint8_t eeprom_message[64];
      // Read last 64B of EEPROM
      EEPROMRead((uint32_t *)eeprom_message, UNLOCK_EEPROM_LOC, UNLOCK_EEPROM_SIZE);

      // Write out full flag if applicable
      uart_write(HOST_UART, eeprom_message, UNLOCK_EEPROM_SIZE);

      sendAckSuccess();
      //send_board_message(&message);

      startCar();
    } else {
      //uart_write(HOST_UART, "FAIL", (uint32_t)8);
      sendAckFailure();
    }
  }
}

/**
 * @brief Function that handles starting of car - feature list
 */
void startCar(void) {
  // Create a message struct variable for receiving data
  MESSAGE_PACKET message;
  uint8_t buffer[256];
  message.buffer = buffer;

  // Receive start message
  receive_board_message_by_type(&message, START_MAGIC);

  FEATURE_DATA *feature_info = (FEATURE_DATA *)buffer;

  // Verify correct car id
  if (memcmp_new((char *)car_id, (char *)feature_info->car_id, 8)) {
    return;
  }
  //uart_write(HOST_UART, (uint8_t*)"here", 5);
  // Print out features for all active features
  
  for (int i = 0; i < feature_info->num_active; i++) {
    uint8_t eeprom_message[64];

    uint32_t offset = feature_info->features[i] * FEATURE_SIZE;

    if (offset > FEATURE_END) {
        offset = FEATURE_END;
    }
    
    EEPROMRead((uint32_t *)eeprom_message, FEATURE_END - offset, FEATURE_SIZE);

    uart_write(HOST_UART, eeprom_message, FEATURE_SIZE);
  }
  
}

/**
 * @brief Function to send successful ACK message
 */
void sendAckSuccess(void) {
  // Create packet for successful ack and send
  MESSAGE_PACKET message;

  uint8_t buffer[1];
  message.buffer = buffer;
  message.magic = ACK_MAGIC;
  buffer[0] = ACK_SUCCESS;
  message.message_len = 1;

  send_board_message(&message);
}

/**
 * @brief Function to send unsuccessful ACK message
 */
void sendAckFailure(void) {
  // Create packet for unsuccessful ack and send
  MESSAGE_PACKET message;

  uint8_t buffer[1];
  message.buffer = buffer;
  message.magic = ACK_MAGIC;
  buffer[0] = ACK_FAIL;
  message.message_len = 1;

  send_board_message(&message);
}

int memcmp_new(const uint8_t *__s1, const uint8_t *__s2, int n) {
  int i;
  int a = 0;
  for (i = 0; i < n; i++) {
    if (__s1[i] == __s2[i]) {
      a = a || 0;
    }
    else {
      a = a || 1;
    }
  }
  return a;
}
/*
void saveFobState(FLASH_DATA *flash_data)
{
  // Save the FLASH_DATA to flash memory
  FlashErase(CAR_STATE_PTR);
  FlashProgram((uint32_t *)flash_data, CAR_STATE_PTR, FLASH_DATA_SIZE);
}
*/