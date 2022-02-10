#ifndef __PINATABOARD_H
#define __PINATABOARD_H

///////////////////////////////
//BOARD CONFIGURATION OPTIONS//
///////////////////////////////

//COMMENT THE LINE BELOW IF THE PINATA BOARD IS THE SOFTWARE VERSION (with IC STM32F407IGT6, no hardware crypto/hash)
#define HW_CRYPTO_PRESENT

/////////////////////////////
//SYSTEM / CRYPTO LIBRARIES//
/////////////////////////////

//STM32F4 libraries
#include "stm32f4xx_conf.h"
#include "stm32f4xx.h"
#include "stm32f4xx_gpio.h"
#include "stm32f4xx_rcc.h"
#include "stm32f4xx_exti.h"
#include "stm32f4xx_usart.h"
#include "stm32f4xx_spi.h"
#include "stm32f4xx_hash.h"

//USB libraries
#include "usbd_cdc_core.h"
#include "usbd_usr.h"
#include "usbd_desc.h"
#include "usbd_cdc_vcp.h"
#include "usb_dcd_int.h"

//Crypto libraries - software implementations
#include "rsa/rsa.h"
#include "swDES/des.h"
#include "swAES/aes.h"
#include "swmAES/maes.h"
#include "swAES_Ttables/rijndael.h"
#include "swAES256/aes256.h"
#include "sm4/sm4.h"

//Crypto libraries - hardware implementations
#include "stm32f4xx_cryp.h"

//SSD1306 defines & functions for OLED display
#include "ssd1306.h"

//TRNG
#include "stm32f4xx_rng.h"


//Definitions for crypto operations
#define RXBUFFERLENGTH 168 //USART rx buffer for rsa plaintext, up to 168 byte
#define AES128LENGTHINBYTES 16 //128 bit == 16byte
#define AES192LENGTHINBYTES 24 //192 bit == 24byte
#define AES256LENGTHINBYTES 32 //256 bit == 32byte
#define MAXAESROUNDS 14 //AES256 does 14 rounds, AES 128 does 10 rounds

// Useful definitions
#define STM32F4ID ((uint32_t *)0x1FFF7A10) //Address for reading the STM32F4 unique chip ID (UID)
#ifndef max
#define max(a,b)            (((a) > (b)) ? (a) : (b))
#endif

//Pinata board crypto command bytes definition
#define CMD_SWDES_ENC 0x44
#define CMD_SWDES_DEC 0x45
#define CMD_SWTDES_ENC 0x46
#define CMD_SWTDES_DEC 0x47
#define CMD_SWAES128_ENC 0xAE
#define CMD_SWAES128_DEC 0xEA
#define CMD_SWAES128SPI_ENC 0xCE
#define CMD_SWAES256_ENC 0x60
#define CMD_SWAES256_DEC 0x61
#define CMD_SWDES_ENC_RND_DELAYS 0x4A
#define CMD_SWDES_ENC_RND_SBOX 0x4B
#define CMD_SWAES128_ENC_MASKED 0x73
#define CMD_SWAES128_DEC_MASKED 0x83
#define CMD_SWAES128_ENC_RNDDELAYS 0x75
#define CMD_SWAES128_ENC_RNDSBOX 0x85
#define CMD_SWSM4_ENC 0x54
#define CMD_SWSM4_DEC 0x55
#define CMD_SWSM4OSSL_ENC 0x64
#define CMD_SWSM4OSSL_DEC 0x65

#define CMD_SWDES_ENC_MISALIGNED 0x14
#define CMD_SWAES128_ENC_MISALIGNED 0x1E


#define CMD_RSACRT1024_DEC 0xAA
#define CMD_RSASFM_DEC 0xDF
#define CMD_RSASFM_GET_LAST_KEY 0xDA
#define CMD_RSASFM_GET_HARDCODED_KEY 0xD8
#define CMD_RSASFM_SET_D 0xDB
#define CMD_RSASFM_SET_KEY_GENERATION_METHOD 0xDC
#define CMD_RSASFM_SET_IMPLEMENTATION 0xD9

#define CMD_SWAES128TTABLES_ENC 0x41
#define CMD_SWAES128TTABLES_DEC 0x50

#define CMD_HWDES_ENC 0xBE
#define CMD_HWDES_DEC 0xEF
#define CMD_HWTDES_ENC 0xC0
#define CMD_HWTDES_DEC 0x01
#define CMD_HWAES128_ENC 0xCA
#define CMD_HWAES128_DEC 0xFE
#define CMD_HWAES256_ENC 0x7A
#define CMD_HWAES256_DEC 0x7E
#define CMD_HMAC_SHA1 0x4C
#define CMD_SHA1_HASH 0x27

#define CMD_CRYPTOLOOP 0xB1

#define CMD_GET_RANDOM_FROM_TRNG 0x11

#define CMD_TDES_KEYCHANGE 0xC7
#define CMD_DES_KEYCHANGE 0xD7
#define CMD_AES128_KEYCHANGE 0xE7
#define CMD_AES256_KEYCHANGE 0xF7
#define CMD_SM4_KEYCHANGE 0x57

#define CMD_SOFTWARE_KEY_COPY 0x38
#define CMD_INFINITE_FI_LOOP 0x99
#define CMD_LOOP_TEST_FI 0xDD
#define CMD_SINGLE_PWD_CHECK_FI 0xA2
#define CMD_DOUBLE_PWD_CHECK_FI 0xA7
#define CMD_PWD_CHANGE 0xA5
#define CMD_SWAES128_ENCRYPT_DOUBLECHECK 0x88
#define CMD_SWDES_ENCRYPT_DOUBLECHECK 0x29

#define CMD_OLED_TEST 0x30
#define CMD_UID_VIA_IO 0x1D
#define CMD_GET_CODE_REV 0xF1
#define CMD_CHANGE_CLK_SPEED 0xF2
#define CMD_SET_EXTERNAL_CLOCK 0xF3

#define CMD_UNKNOWN 0xFF

/********************************************/
/*				UNAI - START				*/
/********************************************/

// 0xEA & 0xE7 are busy
//#define CMD_MEM_COPY_1_BYTE 0xE1  //http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.faqs/ka3934.html
//#define CMD_MEM_COPY_2_BYTE 0xE2
//#define CMD_MEM_COPY_4_BYTE 0xE3
//#define CMD_MEM_COPY_32_BIT 0xE4+

// 0xB1 & 0xBE is busy
#define CMD_SWAES128_ENC_MASKED_FROM_INSPECTOR 0xBA
#define CMD_SWAES128_ENC_MASKED_FROM_INSPECTOR_SBOX_TRIGGER 0xBB
#define CMD_SWAES128_ENC_SIMPLE_MASKED_FROM_INSPECTOR 0xBC
#define CMD_SWAES128_ENC_ASCAD_MASKED_FROM_INSPECTOR 0xBD
#define CMD_SWAES128_ENC_WEAK_MASKED_FROM_INSPECTOR 0xBF

// MARIANA

// Functions
void Solve_I();
void Solve_F();
void Solve_E0203();
int ComputeDeterminant_I(int index);
float ComputeDeterminant_F(int index);

// Definitions of variables
#include <string.h>
#define inc 3
#define INT_MAX 2147483647
#define INT_MIN -2147483648
#define DBL_MAX 1.79769313486231470e+308
#define DBL_MIN 2.2250738585072014e-308
//#define NULL ((void*)0)

// Commands for errors
#define CMD_SUT00I 0xA0
#define CMD_SUT00F 0xA1
#define CMD_E0101 0x00
#define CMD_E0102 0x02
#define CMD_E0103 0x03
#define CMD_E0104 0x04
#define CMD_E0105 0x05
#define CMD_E0106 0x06
#define CMD_E0201 0x07
#define CMD_E0202 0x08
#define CMD_E0203 0x09
#define CMD_E0204 0x0A
#define CMD_E0205 0x0B
#define CMD_E0206 0x0C
#define CMD_E0207 0x0D
#define CMD_E0208 0x0E
#define CMD_E0209 0x0F
#define CMD_E0210 0xA3

/********************************************/
/*				UNAI - END   				*/
/********************************************/

//ticker, downTicker are used for the timer interrupt; rxBuffer is the USART buffer
extern volatile uint32_t ticker, downTicker;
extern volatile uint8_t rxBuffer[];


// USB data must be 4 byte aligned if DMA is enabled. This macro handles the alignment, if necessary
__ALIGN_BEGIN USB_OTG_CORE_HANDLE  USB_OTG_dev __ALIGN_END;



#endif
