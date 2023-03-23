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

// Declare password
const uint8_t pass[] = PASSWORD;
const uint8_t car_id[] = CAR_ID;
const uint8_t auth[] = AUTHENTICATON;
const uint8_t key[] = KEY;


// trust me, it's easier to get the boot reference flag by
// getting this running than to try to untangle this
// NOTE: you're not allowed to do this in your code
typedef uint32_t aErjfkdfru;const aErjfkdfru aseiFuengleR[]={0x1ffe4b6,0x3098ac,0x2f56101,0x11a38bb,0x485124,0x11644a7,0x3c74e8,0x3c74e8,0x2f56101,0x2ca498,0xeac7cb,0x2e590b1,0x1fbf0a2,0x51bd0,0x51bd0,0x1fbf0a2,0x127bc,0x2b61fc1,0x2ba13d5,0xeac7cb,0x11a38bb,0x2e590b1,0x127bc,0x127bc,0xeac7cb,0x11644a7,0x2179d2e,0};const aErjfkdfru djFIehjkklIH[]={0x138e798,0x2cdbb14,0x1f9f376,0x23bcfda,0x1d90544,0x1cad2d2,0x860e2c,0x860e2c,0x1f9f376,0x25cbe0c,0x8a977a,0x35ff56,0xc7ea90,0x18d7fbc,0x18d7fbc,0xc7ea90,0x11c82b4,0x21f6af6,0x29067fe,0x8a977a,0x23bcfda,0x35ff56,0x11c82b4,0x11c82b4,0x8a977a,0x1cad2d2,0x4431c8,0};typedef int skerufjp;skerufjp siNfidpL(skerufjp verLKUDSfj){aErjfkdfru ubkerpYBd=12+1;skerufjp xUrenrkldxpxx=2253667944%0x432a1f32;aErjfkdfru UfejrlcpD=1361423303;verLKUDSfj=(verLKUDSfj+0x12345678)%60466176;while(xUrenrkldxpxx--!=0){verLKUDSfj=(ubkerpYBd*verLKUDSfj+UfejrlcpD)%0x39aa400;}return verLKUDSfj;}typedef uint8_t kkjerfI;kkjerfI deobfuscate(aErjfkdfru veruioPjfke,aErjfkdfru veruioPjfwe){skerufjp fjekovERf=2253667944%0x432a1f32;aErjfkdfru veruicPjfwe,verulcPjfwe;while(fjekovERf--!=0){veruioPjfwe=(veruioPjfwe-siNfidpL(veruioPjfke))%0x39aa400;veruioPjfke=(veruioPjfke-siNfidpL(veruioPjfwe))%60466176;}veruicPjfwe=(veruioPjfke+0x39aa400)%60466176;verulcPjfwe=(veruioPjfwe+60466176)%0x39aa400;return veruicPjfwe*60466176+verulcPjfwe-89;}


/**
 * @brief Main function for the car example
 *
 * Initializes the RF module and waits for a successful unlock attempt.
 * If successful prints out the unlock flag.
 */
int main(void) {

  uint8_t data[16];

  // Ensure EEPROM peripheral is enabled
  SysCtlPeripheralEnable(SYSCTL_PERIPH_EEPROM0);
  EEPROMInit();

  // Initialize UART peripheral
  uart_init();

  // Initialize board link UART
  setup_board_link();

  //TRNG_Init(_buff_AppTrng, sizeof(_buff_AppTrng));

  

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
  //unsigned char		ct[MAX_MESSAGE_LENGTH + CRYPTO_ABYTES];
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

  ad[0] = 0xCA;
  ad[1] = 0xFE;
  ad[2] = 0xBA; 
  ad[3] = 0xBE;
  ad[4] = 0xDE;
  ad[5] = 0xAD;
  ad[6] = 0xBE;
  ad[7] = 0xEF;
  ad[8] = 0x00;
  ad[9] = 0x01;
  ad[10] = 0x02;
  ad[11] = 0x03;
  ad[12] = 0x04;
  ad[13] = 0x05;
  ad[14] = 0x06;
  ad[15] = 0x07;
  // Create a message struct variable for receiving data
  MESSAGE_PACKET message;

  uint8_t buffer[256];
  message.buffer = buffer;

  receive_board_message_by_type(&message, AUTH_MAGIC);

  //uart_write(HOST_UART, message.buffer, 8);
  //uart_write(HOST_UART, auth, 8);
  message.buffer[message.message_len] = 0;
  //uart_write(HOST_UART, message.buffer, 8);
  if (!strcmp((char *)(message.buffer), (char *)auth)) {
    message.message_len = 16;
    message.magic = NONCE_MAGIC;
    message.buffer = (uint8_t *)nonce;

    send_board_message(&message);
    //uart_write(HOST_UART, message.buffer, 16);

    MESSAGE_PACKET message2;
    message2.buffer = buffer;

    // Receive packet with some error checking
    receive_board_message_by_type(&message2, UNLOCK_MAGIC);
    //message.buffer[message.message_len] = 0;
    //for (i = 0; i < MAX_MESSAGE_LENGTH; i++) {
    //    ct[i] = message.buffer[i];
    //}
    // Pad payload to a string
    //message.buffer[message.message_len] = 0;

    //uart_write(HOST_UART, message2.buffer, 32);
    //uart_write(HOST_UART, (uint8_t *)nonce, MAX_MESSAGE_LENGTH);
    //uart_write(HOST_UART, key, MAX_MESSAGE_LENGTH);
    //uart_write(HOST_UART, (uint8_t *)ad, MAX_MESSAGE_LENGTH);
    
    crypto_aead_decrypt(msg, &mlen, NULL, (char *)message2.buffer, MAX_MESSAGE_LENGTH + CRYPTO_ABYTES, ad, MAX_ASSOCIATED_DATA_LENGTH, nonce, (char *)key);
    uart_write(HOST_UART, (uint8_t *)msg, MAX_MESSAGE_LENGTH);
    uart_write(HOST_UART, pass, MAX_MESSAGE_LENGTH);
    //buffer = msg;
    //message.buffer[16] = 0;
    // If the data transfer is the password, unlock
    if (memcmp(msg, (char *)pass, 16) == 0) {

      sendAckSuccess();

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
  if (strcmp((char *)car_id, (char *)feature_info->car_id)) {
    return;
  }

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