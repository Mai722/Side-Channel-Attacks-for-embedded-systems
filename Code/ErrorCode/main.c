//Main file for Riscure Pinata Board rev2.2
//Riscure 2014, 2015, 2016, 2017
//
//Code revision: 	2.2 -- 20171221v1
//
//IMPORTANT:
//Configuration options for the board (presence of hardware crypto engine) are defined in main.h
//
//Changelog from code revision 2.2 from v2.1
// Added SM4 textbook software implementation (code (C) Odzhan) and OpenSSL SM4 software implementation
// Added DES with initial random delay to force the use of static alignment of the trace
// Bumped FW version to 2.2
//
//Changelog for code revision 2.1 from v1.0:
// Disabled SysTick system timer for cleaner SCA traces (less time jitter, no big spikes every 1ms)
// Added byte-wise copy of a 16-byte array SRAM-SRAM (for Key-loading Template Analysis)
// Added more crypto implementations: SW TDES, SW AES256 curious implementation from Internet, RSA-512 S&M always (SFM, straight forward method)
// Added software AES with trigger pin disabled and a SPI transfer before crypto start (for triggering on SPI bus)
// Added commands for computing HMAC-SHA1 and SHA1 for boards with the hw crypto engine
// Added a new command for checking which Pinata Software Version is programmed on the board
// Added command to request STM32F4 chip UID
// Board now replies zeroes (without trigger signal) if HW crypto/hash command is sent to Pinata board without HW crypto/hash engine
// Added clock source switching commands
// Added clock speed switching commands
// Added commands for FI on password check (single and double check strategies) and infinite loop
// Fixed a stack smash when running AES key schedule on AES T-tables implementation
// Added command to ask for a random number from the TRNG
// Added software DES and AES with a double check for Advanced FI (DFA) purposes
// Added crypto with textbook SW countermeasures: DES with Random delays or S-box shuffling; AES with masking, random delays or S-box shuffling


#include "main.h"

//Local functions
void get_bytes(uint32_t nbytes, uint8_t* ba);
void send_bytes(uint32_t nbytes, uint8_t* ba);
void get_char(uint8_t *ch);
void send_char(uint8_t ch);
void readFromCharArray(uint8_t *ch);
void readByteFromInputBuffer(uint8_t *ch);
void init();
void CrashGracefully();
void usart_init();
void oled_init();
void RNG_Enable();
void RNG_Disable();

//Variables, constants and structures
const uint8_t defaultKeyDES[8] = { 0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef };
const uint8_t defaultKeyTDES[24] = { 0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 ,0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef }; //Default is TDES in 2key mode, DESkey1==DESkey3
const uint8_t defaultKeyAES[16] = { 0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
const uint8_t defaultKeyAES256[32] = { 0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
									   0xda, 0xba, 0xda, 0xba, 0xd0, 0x00, 0x00, 0xc0, 0x00, 0x01, 0xc0, 0xff, 0xee, 0x55, 0xde, 0xad };
const uint8_t defaultKeySM4[16] = { 0x52, 0x69, 0x73, 0x63, 0x75, 0x72, 0x65, 0x43, 0x68, 0x69, 0x6e, 0x61, 0x32, 0x30, 0x31, 0x37 };
const uint8_t glitched[] = { 0xFA, 0xCC };
const int bootLoopCount=168000;
const uint8_t cmdByteIsWrong[] = { 'B','a','d','C','m','d','\n',0x00};
const uint8_t OLED_bootNormalScreen[] =   { 'B','o','o','t',' ','c','h','e','c','k',' ','o','k',' ',' ',' ',' ',' ',' ',' ',' '};
const uint8_t OLED_bootGlitchedScreen[] = { 'B','o','o','t',' ','c','h','e','c','k',' ','g','l','i','t','c','h','e','d','!','!'};
const uint8_t OLED_initScreen[] = { 'P','i','n','a','t','a',' ','B','o','a','r','d',' ','2','.','1',' ',' ',' ',' ',' ','(','c',')','R','i','s','c','u','r','e',' ','2','0','1','7'};
const uint8_t zeros[20]={'0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0'};
const uint8_t codeVersion[] = { 'V','e','r',' ','2','.','2',0x00};
const uint8_t defaultPasswd[] = {0x02,0x06,0x02,0x08};

volatile uint8_t rxBuffer[RXBUFFERLENGTH] = { };
volatile uint32_t ticker, downTicker;
volatile uint8_t usbSerialEnabled=0;
volatile int busyWait1;
volatile uint8_t clockspeed=168;
volatile uint8_t clockSource=0;

/********************************************/
/*				UNAI - START				*/
/********************************************/

// memCpy variables
uint8_t dest8[4];	//unsigned int * const dest;
uint8_t data8[4];
uint32_t dest32[4];	//unsigned int * const dest;
uint32_t data32[4];

// dummyDelay function
void dummyDelay(int i){while (i!=0){i--;}}

// Masked AES variables
volatile uint8_t aes_plaintext[16];
volatile uint8_t key[16];
volatile uint8_t mask[16];
volatile uint8_t mask1;
volatile uint8_t mask2;

// Global variables
//int Matrix_I[inc][inc+1];
//float Matrix_F[inc][inc+1];
int** Matrix_I;
float** Matrix_F;

// Functions

/* INTEGER */

int ComputeDeterminant_I(int index) {
//	syslog(LOG_INFO, "ComputeDeterminant::Begin");

	int M[inc][inc];

	for(int f=0;f<inc;f++) {
		for(int c=0;c<inc;c++) {
			if(c!=index) {
				M[f][c]=Matrix_I[f][c];
			} else {
				M[f][c]=Matrix_I[f][inc];
			}
		}
	}

//	syslog(LOG_INFO, "ComputeDeterminant::End");

//	return  M[0][0]*M[1][1] - M[0][1]*M[1][0];
	return M[0][0]*((M[1][1]*M[2][2])-(M[2][1]*M[1][2])) + M[0][1]*((M[1][2]*M[2][0])-(M[1][0]*M[2][2])) + M[1][0]*((M[2][1]*M[0][2])-(M[0][1]*M[2][2]));

}

void Solve_I() {
//	syslog(LOG_INFO, "Solve::Begin");

	int x,y,d,dx,dy;
	int z,dz;

	d=ComputeDeterminant_I(inc);
	dx=ComputeDeterminant_I(inc-3);
	dy=ComputeDeterminant_I(inc-2);
	dz=ComputeDeterminant_I(inc-1);

	x = dx/d;
	y = dy/d;
	z = dz/d;

//	syslog(LOG_INFO, "Solve::End");
}

/* FLOAT */

float ComputeDeterminant_F(int index) {
//	syslog(LOG_INFO, "ComputeDeterminant::Begin");

	float M[inc][inc];

	for(int f=0;f<inc;f++) {
		for(int c=0;c<inc;c++) {
			if(c!=index) {
				M[f][c]=Matrix_F[f][c];
			} else {
				M[f][c]=Matrix_F[f][inc];
			}
		}
	}

//	syslog(LOG_INFO, "ComputeDeterminant::End");

//	return  M[0][0]*M[1][1] - M[0][1]*M[1][0];
	return M[0][0]*((M[1][1]*M[2][2])-(M[2][1]*M[1][2])) + M[0][1]*((M[1][2]*M[2][0])-(M[1][0]*M[2][2])) + M[1][0]*((M[2][1]*M[0][2])-(M[0][1]*M[2][2]));

}

void Solve_F() {
//	syslog(LOG_INFO, "Solve::Begin");

	float x,y,d,dx,dy;
	float z,dz;

	d=ComputeDeterminant_F(inc);
	dx=ComputeDeterminant_F(inc-3);
	dy=ComputeDeterminant_F(inc-2);
	dz=ComputeDeterminant_F(inc-1);

	x = dx/d;
	y = dy/d;
	z = dz/d;

//	syslog(LOG_INFO, "Solve::End");
}

void Solve_E0203() {
//	syslog(LOG_INFO, "Solve::Begin");

	float x,y,d,dx,dy;
	float z,dz;

	d=ComputeDeterminant_F(inc);
	dx=ComputeDeterminant_F(inc-3);
	dy=ComputeDeterminant_F(inc-2);
	dz=ComputeDeterminant_F(inc-1);

	x = dx/d;
	y = dy/d;
	z = dz/d;

	free(Matrix_F);

//	syslog(LOG_INFO, "Solve::End");
}




/********************************************/
/*				UNAI - END   				*/
/********************************************/

////////////////////////////////////////////////////
//MAIN FUNCTION: entry point for the board program//
////////////////////////////////////////////////////
int main(void) {
	uint8_t cmd, tmp;
	volatile int payload_len, i, glitchedBoot, authenticated, counter=0;
	ErrorStatus cryptoCompletedOK=ERROR;
	//We will need ROUNDS + 1 keys to be generated by the key schedule (multiplied by 4 because we can only store 32 bits at a time).
	uint32_t keyScheduleAES[(MAXAESROUNDS + 1) * 4] = { };
	volatile uint8_t keyDES[8];
	volatile uint8_t keyTDES[24];
	volatile uint8_t keyAES[16];
	volatile uint8_t keyLoadingAES[16];
	volatile uint8_t keyAES256[32];
	volatile uint8_t keySM4[16];
	volatile uint8_t password[4];
	aes256_context ctx;
	sm4_ctx ctx_sm4;
	SM4_KEY ctx_sm4_ossl;

	//Set up the system clocks
	SystemInit();
	//Initialize peripherals and select IO interface
	init();

	//Disable SysTick interrupt to avoid spikes every 1ms
	SysTick->CTRL = SysTick_CTRL_CLKSOURCE_Msk | SysTick_CTRL_ENABLE_Msk;

	// If no jumper between PA9, VBUS
	if(!usbSerialEnabled) {
		// Enable USART3 in port gpioC (Pins PC10 TxD,PC11 RxD)
		usart_init();
	}

	// Optional peripherals: enable SPI and GPIO pins for OLED display
	oled_init();
	oled_clear();

	// Initialize & load default cryptographic keys from FLASH memory
	// Load RSACRT parameters
	rsa_crt_init();
	// Load RSASFM parameters
	rsa_sfm_init();
	// Load default keys for DES, TDES, AES from non volatile memory
	for (i = 0; i < 8; i++) keyDES[i] = defaultKeyDES[i];
	for (i = 0; i < 24; i++) keyTDES[i] = defaultKeyTDES[i];
	for (i = 0; i < 16; i++) keyAES[i] = defaultKeyAES[i];
	for (i = 0; i < 4; i++) password[i] = defaultPasswd[i];

	//Loop for trivial Boot glitching; display boot screen with glitched status
	//PC1 can be used as trigger pin for boot glitching
	GPIOC->BSRRL = GPIO_Pin_1; //PC1 3.3V

	glitchedBoot=0;
	authenticated=0;
	for (counter=0;counter<bootLoopCount;){
		counter++;
	}
	GPIOC->BSRRH = GPIO_Pin_1; //PC1 0V
	//Mock-up of security check: counter in a loop
	if (counter != bootLoopCount) {
		glitchedBoot = 1;
	}

	if (glitchedBoot) {
		oled_sendchars(21,OLED_bootGlitchedScreen);
	} else {
		oled_sendchars(21,OLED_bootNormalScreen);
	}
	oled_sendchars(36,OLED_initScreen);

	//Ver 2.0 and later: init code updates after initial code (to keep similar timing for boot glitching from code version 1.0)
	for (i = 0; i < 32; i++) keyAES256[i] = defaultKeyAES256[i];
	aes256_init(&ctx,keyAES256); //Prepare AES key schedule for software AES256
	for (i = 0; i < 16; i++) keySM4[i] = defaultKeySM4[i];

	//////////////////////
	//MAIN FUNCTION LOOP//
	//////////////////////

	int var_I;
	int var_F;

	int r;
	volatile unsigned int* p;

//	cmd = CMD_E0209;

	while (1) {
		//Main loop variable (re)initialization
		for (i = 0; i < RXBUFFERLENGTH; i++) rxBuffer[i] = 0; //Zero the rxBuffer
		for (i = 0; i < MAXAESROUNDS; i++) keyScheduleAES[i] = 0; //Zero the AES key schedule (T-tables AES implementation)
		charIdx = 0; //RSA: Global variable with offset for reading the ciphertext, init to 0
		payload_len = 0x0000; //RSA: Length of the ciphertext; init to zero, expected values for 1024bit RSA=128byte, 512bit RSA=64byte
		cmd=0;

		//Main processing section: select and execute cipher&mode

		get_char(&cmd);

		switch (cmd) {

		/********************************************/
		/*				ERRORES - START				*/
		/********************************************/
			case CMD_SUT00I:
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on

				var_I = 1;
				Matrix_I = (int **) malloc(inc*sizeof(int*));
				for (int f = 0; f < inc; f++) {
					Matrix_I[f]=(int *) malloc((inc+1)*sizeof(int));
					for (int c=0; c<inc+1; c++) {
						Matrix_I[f][c] = var_I;
						var_I += 1;
					}
				}

				Solve_I();
				free(Matrix_I);

				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_char(cmd);
				break;

			case CMD_E0103:
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on

				// Matrix initialization
				var_I = 1;
				Matrix_I = (int **) malloc(inc*sizeof(int*));
				for (int f = 0; f < inc; f++) {
					Matrix_I[f]=(int *) malloc((inc+1)*sizeof(int));
					for (int c=0; c<inc+1; c++) {
						Matrix_I[f][c] = var_I;
						var_I += 1;
					}
				}

				Solve_I();
				free(Matrix_I);

				// Integer Overflow
				var_I = INT_MAX +1;

				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_char(cmd);
				break;

			case CMD_E0104:
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on

				// Matrix initialization
				var_I = 1;
				Matrix_I = (int **) malloc(inc*sizeof(int*));
				for (int f = 0; f < inc; f++) {
					Matrix_I[f]=(int *) malloc((inc+1)*sizeof(int));
					for (int c=0; c<inc+1; c++) {
						Matrix_I[f][c] = var_I;
						var_I += 1;
					}
				}

				Solve_I();
				free(Matrix_I);

				// Integer Underflow
				var_I = INT_MIN -1;

				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_char(cmd);
				break;

			case CMD_E0105:
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on

				// Matrix initialization
				var_I = 1;
				Matrix_I = (int **) malloc(inc*sizeof(int*));
				for (int f = 0; f < inc; f++) {
					Matrix_I[f]=(int *) malloc((inc+1)*sizeof(int));
					for (int c=0; c<inc+1; c++) {
						Matrix_I[f][c] = var_I;
						var_I += 1;
					}
				}

				Solve_I();
				free(Matrix_I);

				// Divide by zero Integer
				var_I = var_I/0;

//				__asm __volatile__(
//					"movs r2, #1\n"
//					"movs r3, #0\n"
//					"udiv r3, r2, r3"
//				);


				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_char(cmd);
				break;

			case CMD_SUT00F:
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on

				// Matrix initialization
				var_F = 1.0;
				Matrix_F = (float **) malloc(inc*sizeof(float*));
				for (int f = 0; f < inc; f++) {
					Matrix_F[f]=(float *) malloc((inc+1)*sizeof(float));
					for (int c=0; c<inc+1; c++) {
						Matrix_F[f][c] = var_F;
						var_F += 1.0;
					}
				}

				Solve_F();
				free(Matrix_F);

				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_char(cmd);
				break;

			case CMD_E0101:
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on

				// Matrix initialization
				var_F = 1.0;
				Matrix_F = (float **) malloc(inc*sizeof(float*));
				for (int f = 0; f < inc; f++) {
					Matrix_F[f]=(float *) malloc((inc+1)*sizeof(float));
					for (int c=0; c<inc+1; c++) {
						Matrix_F[f][c] = var_F;
						var_F += 1.0;
					}
				}

				Solve_F();
				free(Matrix_F);

				//Floating Point Overflow
				var_F = DBL_MAX + 1.0;

				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_char(cmd);
				break;

			case CMD_E0102:
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on

				// Matrix initialization
				var_F = 1.0;
				Matrix_F = (float **) malloc(inc*sizeof(float*));
				for (int f = 0; f < inc; f++) {
					Matrix_F[f]=(float *) malloc((inc+1)*sizeof(float));
					for (int c=0; c<inc+1; c++) {
						Matrix_F[f][c] = var_F;
						var_F += 1.0;
					}
				}

				Solve_F();
				free(Matrix_F);

				//Floating Point Underflow
				var_F = DBL_MIN - 1.0;

				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_char(cmd);
				break;

			case CMD_E0106:
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on

				// Matrix initialization
				var_F = 1.0;
				Matrix_F = (float **) malloc(inc*sizeof(float*));
				for (int f = 0; f < inc; f++) {
					Matrix_F[f]=(float *) malloc((inc+1)*sizeof(float));
					for (int c=0; c<inc+1; c++) {
						Matrix_F[f][c] = var_F;
						var_F += 1.0;
					}
				}

				Solve_F();
				free(Matrix_F);

				//Divide by zero Decimal
				var_F = var_F/0.0;

				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_char(cmd);
				break;

			case CMD_E0201:
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on

				// Matrix initialization
				var_F = 1.0;
				Matrix_F = (float **) malloc(inc*sizeof(float*));
				for (int f = 0; f < inc; f++) {
					Matrix_F[f]=(float *) malloc((inc+1)*sizeof(float));
					for (int c=0; c<inc+1; c++) {
						Matrix_F[f][c] = var_F;
						var_F += 1.0;
					}
				}

				Solve_F();
				free(Matrix_F);

				//Segmentation Fault
				char *onlyrd = "string";
				onlyrd[0] = 'n';

				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_char(cmd);
				break;

			case CMD_E0202:
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on

				// Matrix initialization
				var_F = 1.0;
				Matrix_F = (float **) malloc(inc*sizeof(float));
				for (int f = 0; f < inc; f++) {
					Matrix_F[f]=(float *) malloc((inc+1)*sizeof(float));
					for (int c=0; c<inc+1; c++) {
						Matrix_F[f][c] = var_F;
						var_F += 1.0;
					}
				}

				Solve_F();
				free(Matrix_F);

				//Buffer Overflow
				char buff[10];
				char cadena[] = "This solution will overflow the buffer\n";
				strcpy(buff, cadena);

				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_char(cmd);
				break;

			case CMD_E0203:
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on

				// Matrix initialization
				var_F = 1.0;
				Matrix_F = (float **) malloc(inc*sizeof(float*));
				for (int f = 0; f < inc; f++) {
					Matrix_F[f]=(float *) malloc((inc+1)*sizeof(float));
					for (int c=0; c<inc+1; c++) {
						Matrix_F[f][c] = var_F;
						var_F += 1.0;
					}
				}

				Solve_E0203();

				//Double free
				free(Matrix_F);

				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_char(cmd);
				break;

			case CMD_E0204:
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on

				// Matrix initialization
				var_F = 1.0;
				Matrix_F = (float **) malloc(inc*sizeof(float*));
				for (int f = 0; f < inc; f++) {
					Matrix_F[f]=(float *) malloc((inc+1)*sizeof(float));
					for (int c=0; c<inc+1; c++) {
						Matrix_F[f][c] = var_F;
						var_F += 1.0;
					}
				}

				Solve_F();
				free(Matrix_F);

				//Null pointer dereference
//				char *str;
//			  	char* ptr = NULL;
//			  	strcpy(str,ptr);

			  	int *ptr;
			  	int val = *ptr;

				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_char(cmd);
				break;

			case CMD_E0205:
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on

				// Matrix initialization
				var_F = 1.0;
				Matrix_F = (float **) malloc(inc*sizeof(float*));
				for (int f = 0; f < inc; f++) {
					Matrix_F[f]=(float *) malloc((inc+1)*sizeof(float));
					for (int c=0; c<inc+1; c++) {
						Matrix_F[f][c] = var_F;
						var_F += 1.0;
					}
				}

				Solve_F();

				//Out of Bounds Write A
				Matrix_F[3][4] = 1.0;
				free(Matrix_F);

				//Out of Bounds Write B - Illegal access
				//p = (unsigned int*)0x00100000;  // 0x00100000-0x07FFFFFF is reserved on STM32F4
				//*p = 0x00BADA55;

				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_char(cmd);
				break;

			case CMD_E0206:
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on

				// Matrix initialization
				var_F = 1.0;
				Matrix_F = (float **) malloc(inc*sizeof(float*));
				for (int f = 0; f < inc; f++) {
					Matrix_F[f]=(float *) malloc((inc+1)*sizeof(float));
					for (int c=0; c<inc+1; c++) {
						Matrix_F[f][c] = var_F;
						var_F += 1.0;
					}
				}

				Solve_F();

				//Out of Bounds Read A
				var_F = Matrix_F[3][4];
				free(Matrix_F);

				//Out of Bounds Read B - Illegal access
				//p = (unsigned int*)0x00100000;        // 0x00100000-0x07FFFFFF is reserved on STM32F4
				//r = *p;

				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_char(cmd);
				break;

			case CMD_E0207:
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on

				// Matrix initialization
				var_F = 1.0;
				Matrix_F = (float **) malloc(inc*sizeof(float*));
				for (int f = 0; f < inc; f++) {
					Matrix_F[f]=(float *) malloc((inc+1)*sizeof(float));
					for (int c=0; c<inc+1; c++) {
						Matrix_F[f][c] = var_F;
						var_F += 1.0;
					}
				}

				Solve_F();
				free(Matrix_F);

				//Out of Memory
				Matrix_F = (float **) malloc(10000*sizeof(float*));
				for (int f = 0; f < 10000; f++) {
					Matrix_F[f]=(float *) malloc((1000+1)*sizeof(float));
				}

				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_char(cmd);
				break;

			case CMD_E0208:
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on

				// Matrix initialization
				var_F = 1.0;
				Matrix_F = (float **) malloc(inc*sizeof(float*));
				for (int f = 0; f < inc; f++) {
					Matrix_F[f]=(float *) malloc((inc+1)*sizeof(float));
					for (int c=0; c<inc+1; c++) {
						Matrix_F[f][c] = var_F;
						var_F += 1.0;
					}
				}

				Solve_F();
				free(Matrix_F);

				//Stack Overflow
				for(int i=0; i<16116; i++) {
					__asm __volatile__(
						"push {r1}\n"
					);
				}

				__asm __volatile__(
					"push {r1}\n"
				);

				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_char(cmd);
				break;

			case CMD_E0209:
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on

				// Matrix initialization
				var_F = 1.0;
				Matrix_F = (float **) malloc(inc*sizeof(float*));
				for (int f = 0; f < inc; f++) {
					Matrix_F[f]=(float *) malloc((inc+1)*sizeof(float));
					for (int c=0; c<inc+1; c++) {
						Matrix_F[f][c] = var_F;
						var_F += 1.0;
					}
				}

				Solve_F();
				free(Matrix_F);

				//Stack Underflow

				//STACK_SIZE = 0x00004000 = 16384
				//16384/4 bytes = 4096 posiciones de memoria

				for(int i=0; i<4096*3+1452; i++){
				__asm __volatile__(
						"pop {r1}\n"
						);
				}

				__asm __volatile__(
						"pop {r1}\n"
						);


				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_char(cmd);
				break;

			case CMD_E0210:
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on

				// Matrix initialization
				var_F = 1.0;
				Matrix_F = (float **) malloc(inc*sizeof(float*));
				for (int f = 0; f < inc; f++) {
					Matrix_F[f]=(float *) malloc((inc+1)*sizeof(float));
					for (int c=0; c<inc+1; c++) {
						Matrix_F[f][c] = var_F;
						var_F += 1.0;
					}
				}

				Solve_F();
				free(Matrix_F);

				//Unaligned Access
//				p = (unsigned int*)0x20000002; //Not word aligned address
//				r = *p;

				__asm __volatile__(
						"ldr r3, =0x20000000 \n"
						);

				__asm __volatile__(
						"add r3, r3, #2\n"
						);

				//Load word from unaligned address
				__asm __volatile__(
						"ldr r3, [r3]\n"
						"str r3, [sp]\n"
						);

				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_char(cmd);
				break;

		/********************************************/
		/*				ERRORES - END				*/
		/********************************************/

				/********************************************/
				/*				UNAI - START				*/
				/********************************************/

//			case CMD_MEM_COPY_1_BYTE:
//				dest8[0]=0x00;
//				data8[0]=0x00;
//				get_bytes(1, data8); // Receive DES plaintext
//				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
//				dummyDelay(751); //1ms = 16797 // 44,94 ms = 751
//				memcpy(dest8, data8, 1);
//				dummyDelay(751); //1ms
//				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
//				send_bytes(1, dest8); // Transmit back ciphertext via UART
//				break;
//
//			case CMD_MEM_COPY_2_BYTE:
//				dest8[0]=0x00;
//				dest8[1]=0x00;
//				data8[0]=0x00;
//				data8[1]=0x00;
//				get_bytes(2, data8); // Receive DES plaintext
//				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
//				dummyDelay(751); //1ms = 16797 // 44,94 ms = 751
//				memcpy(dest8, data8, 2);
//				dummyDelay(751); //1ms
//				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
//				send_bytes(2, dest8); // Transmit back ciphertext via UART
//				break;
//
//			case CMD_MEM_COPY_4_BYTE:
//				dest8[0]=0x00;
//				dest8[1]=0x00;
//				dest8[2]=0x00;
//				dest8[3]=0x00;
//				data8[0]=0x00;
//				data8[1]=0x00;
//				data8[2]=0x00;
//				data8[3]=0x00;
//				get_bytes(4, data8); // Receive DES plaintext
//				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
//				dummyDelay(751); //1ms = 16797 // 44,94 ms = 751
//				memcpy(dest8, data8, 4);
//				dummyDelay(751); //1ms
//				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
//				send_bytes(4, dest8); // Transmit back ciphertext via UART
//				break;
//
//			case CMD_MEM_COPY_32_BIT:
//				dest32[0]=0x00000000;
//				data32[0]=0x00000000;
//				get_bytes(1, data32); // Receive DES plaintext
//				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
//				dummyDelay(751); //1ms = 16797 // 44,94 ms = 751
//				memcpy(dest32, data32, 1);
//				dummyDelay(751); //1ms
//				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
//				send_bytes(1, dest32); // Transmit back ciphertext via UART
//				break;

			//Software masked AES128 - encrypt (Simple Masking)
			case CMD_SWAES128_ENC_SIMPLE_MASKED_FROM_INSPECTOR:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				simple_mAES128_ECB_encrypt(rxBuffer, keyAES, rxBuffer + AES128LENGTHINBYTES); //Trigger is coded inside aes function, includes masking process
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back ciphertext via UART
				break;

			//Software masked AES128 - encrypt (Masks from inspector)
			case CMD_SWAES128_ENC_MASKED_FROM_INSPECTOR:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				memcpy(aes_plaintext, rxBuffer, 16);

				/**************************************
				Aqui, donde se hace otra copia de la llave en memoria,
				es un buen punto para "simular" un ataque de memcopy
			 	**************************************/
				get_bytes(16, rxBuffer); // Receive key
				memcpy(key, rxBuffer, 16);
				/**************************************/
				/**************************************/
				get_bytes(16, rxBuffer); // Receive mask
				memcpy(mask, rxBuffer, 16);

				get_bytes(1, rxBuffer); // Receive mask1
				mask1 = *rxBuffer;

				get_bytes(1, rxBuffer); // Receive mask2
				mask2 = *rxBuffer;

				mAES128_ECB_encrypt_masks_from_inspector(aes_plaintext, key, mask, mask1, mask2, rxBuffer + AES128LENGTHINBYTES); //Trigger is coded inside aes function, includes masking process
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back ciphertext via UART
				break;

			//Software masked AES128 - encrypt (Masks from inspector & sbox trigger)
			case CMD_SWAES128_ENC_MASKED_FROM_INSPECTOR_SBOX_TRIGGER:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				memcpy(aes_plaintext, rxBuffer, 16);

				/**************************************
				Aqui, donde se hace otra copia de la llave en memoria,
				es un buen punto para "simular" un ataque de memcopy
			 	**************************************/
				get_bytes(16, rxBuffer); // Receive key
				memcpy(key, rxBuffer, 16);
				/**************************************/
				/**************************************/
				get_bytes(16, rxBuffer); // Receive mask
				memcpy(mask, rxBuffer, 16);

				get_bytes(1, rxBuffer); // Receive mask1
				mask1 = *rxBuffer;

				get_bytes(1, rxBuffer); // Receive mask2
				mask2 = *rxBuffer;

				mAES128_ECB_encrypt_masks_from_inspector_sbox_trigger(aes_plaintext, key, mask, mask1, mask2, rxBuffer + AES128LENGTHINBYTES); //Trigger is coded inside aes function, includes masking process
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back ciphertext via UART
				break;

			//Software masked AES128 - encrypt (Masks from inspector)
			case CMD_SWAES128_ENC_ASCAD_MASKED_FROM_INSPECTOR:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				memcpy(aes_plaintext, rxBuffer, 16);

				/**************************************
				Aqui, donde se hace otra copia de la llave en memoria,
				es un buen punto para "simular" un ataque de memcopy
			 	**************************************/
				get_bytes(16, rxBuffer); // Receive key
				memcpy(key, rxBuffer, 16);
				/**************************************/
				/**************************************/
				get_bytes(16, rxBuffer); // Receive mask
				memcpy(mask, rxBuffer, 16);

				get_bytes(1, rxBuffer); // Receive mask1
				mask1 = *rxBuffer;

				get_bytes(1, rxBuffer); // Receive mask2
				mask2 = *rxBuffer;

				mAES128_ECB_encrypt_ASCAD_masks_from_inspector(aes_plaintext, key, mask, mask1, mask2, rxBuffer + AES128LENGTHINBYTES); //Trigger is coded inside aes function, includes masking process
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back ciphertext via UART
				break;

			case CMD_SWAES128_ENC_WEAK_MASKED_FROM_INSPECTOR:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				memcpy(aes_plaintext, rxBuffer, 16);

				/**************************************
				Aqui, donde se hace otra copia de la llave en memoria,
				es un buen punto para "simular" un ataque de memcopy
			 	**************************************/
				get_bytes(16, rxBuffer); // Receive key
				memcpy(key, rxBuffer, 16);
				/**************************************/
				/**************************************/
				get_bytes(16, rxBuffer); // Receive mask
				memcpy(mask, rxBuffer, 16);

				get_bytes(1, rxBuffer); // Receive mask1
				mask1 = *rxBuffer;

				get_bytes(1, rxBuffer); // Receive mask2
				mask2 = *rxBuffer;

				mAES128_ECB_encrypt_WEAK_masks_from_inspector(aes_plaintext, key, mask, mask1, mask2, rxBuffer + AES128LENGTHINBYTES); //Trigger is coded inside aes function, includes masking process
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back ciphertext via UART
				break;




			/********************************************/
			/*				UNAI - END					*/
			/********************************************/

			/////////Software crypto commands/////////
			//Software DES - encrypt
			case CMD_SWDES_ENC:
				get_bytes(8, rxBuffer); // Receive DES plaintext
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				des(keyDES, rxBuffer, ENCRYPT); // Perform software DES encryption
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_bytes(8, rxBuffer); // Transmit back ciphertext via UART
				break;

			//Software DES - decrypt
			case CMD_SWDES_DEC:
				get_bytes(8, rxBuffer); // Receive DES ciphertext
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				des(keyDES, rxBuffer, DECRYPT); // Perform software DES decryption
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_bytes(8, rxBuffer); // TransmiDt back plaintext via UART
				break;

			//Software TDES - encrypt
			case CMD_SWTDES_ENC:
				get_bytes(8, rxBuffer); // Receive TDES plaintext
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				des(keyTDES,   rxBuffer, ENCRYPT); // Perform software DES encryption, key1
				des(keyTDES+8, rxBuffer, DECRYPT); // Perform software DES decryption, key2
				des(keyTDES+16,rxBuffer, ENCRYPT); // Perform software DES encryption, key3
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_bytes(8, rxBuffer); // Transmit back ciphertext via UART
				break;

			//Software TDES - decrypt
			case CMD_SWTDES_DEC:
				get_bytes(8, rxBuffer); // Receive TDES ciphertext
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				des(keyTDES,   rxBuffer, DECRYPT); // Perform software DES decryption, key1
				des(keyTDES+8, rxBuffer, ENCRYPT); // Perform software DES encryption, key2
				des(keyTDES+16,rxBuffer, DECRYPT); // Perform software DES decryption, key3
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_bytes(8, rxBuffer); // Transmit back plaintext via UART
				break;

			//Software AES128 - encrypt
			case CMD_SWAES128_ENC:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				AES128_ECB_encrypt(rxBuffer, keyAES, rxBuffer + AES128LENGTHINBYTES); //Trigger is coded inside aes function after key expansion
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back ciphertext via UART
				break;

			//Software AES128 - encrypt with SPI transmission at beginning, NO TRIGGER ON PC2
			case CMD_SWAES128SPI_ENC:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				//4 byte SPI transmission to simulate access to e.g. external FLASH; sending 0xDECAFFED
				send_OLEDcmd_SPI(0xDE);
				send_OLEDcmd_SPI(0xCA);
				send_OLEDcmd_SPI(0xFF);
				send_OLEDcmd_SPI(0xED);
				AES128_ECB_encrypt_noTrigger(rxBuffer, keyAES, rxBuffer + AES128LENGTHINBYTES);
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back ciphertext via UART
				break;

			//Software AES128 - decrypt
			case CMD_SWAES128_DEC:
				get_bytes(16, rxBuffer); // Receive AES ciphertext
				AES128_ECB_decrypt(rxBuffer, keyAES, rxBuffer + AES128LENGTHINBYTES); //Trigger is coded inside aes function after key expansion
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back plaintext via UART
				break;

			//Software AES256 - encrypt
			case CMD_SWAES256_ENC:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				aes256_encrypt_ecb(&ctx, rxBuffer); // Perform software AES256 encryption
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_bytes(16, rxBuffer); // Transmit back ciphertext via UART
				break;

			//Software AES256 - decrypt
			case CMD_SWAES256_DEC:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				aes256_decrypt_ecb(&ctx, rxBuffer); // Perform software AES256 encryption
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_bytes(16, rxBuffer); // Transmit back ciphertext via UART
				break;

			//Software SM4 - encrypt
			case CMD_SWSM4_ENC:
				get_bytes(16, rxBuffer); // Receive SM4 plaintext
				sm4_setkey(&ctx_sm4, keySM4, SM4_ENCRYPT); //Configure SM4 key schedule for encryption
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				sm4_encrypt(&ctx_sm4,rxBuffer); //Perform SM4 crypto
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_bytes(16, rxBuffer); // Transmit back ciphertext via UART
				break;

			//Software SM4 - decrypt
			case CMD_SWSM4_DEC:
				get_bytes(16, rxBuffer); // Receive SM4 ciphertext
				sm4_setkey(&ctx_sm4, keySM4, SM4_DECRYPT); //Configure SM4 key schedule for decryption
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				sm4_encrypt(&ctx_sm4,rxBuffer); //Perform SM4 crypto
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_bytes(16, rxBuffer); // Transmit back plaintext via UART
				break;

			//Software SM4 OpenSSL implementation- encrypt
			case CMD_SWSM4OSSL_ENC:
				get_bytes(16, rxBuffer); // Receive SM4 plaintext
				SM4_set_key(keySM4, &ctx_sm4_ossl); //Configure SM4 key schedule
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				SM4_encrypt(rxBuffer,rxBuffer+SM4_BLOCK_SIZE,&ctx_sm4_ossl); //Perform SM4 encryption (openSSL code)
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_bytes(16, rxBuffer+SM4_BLOCK_SIZE); // Transmit back ciphertext via UART
				break;

			//Software SM4 OpenSSL implementation - decrypt
			case CMD_SWSM4OSSL_DEC:
				get_bytes(16, rxBuffer); // Receive SM4 plaintext
				SM4_set_key(keySM4, &ctx_sm4_ossl); //Configure SM4 key schedule
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				SM4_decrypt(rxBuffer,rxBuffer+SM4_BLOCK_SIZE,&ctx_sm4_ossl); //Perform SM4 decryption (openSSL code)
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_bytes(16, rxBuffer+SM4_BLOCK_SIZE); // Transmit back ciphertext via UART
				break;

			//Software DES - encrypt with misalignment at beginning of trigger (to practice static align)
			case CMD_SWDES_ENC_MISALIGNED:
				get_bytes(8, rxBuffer); // Receive DES plaintext
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				desMisaligned(keyDES, rxBuffer, ENCRYPT); // Perform software DES encryption
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_bytes(8, rxBuffer); // Transmit back ciphertext via UART
				break;

			case CMD_SWAES128_ENC_MISALIGNED:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				AES128_ECB_encrypt_misaligned(rxBuffer, keyAES, rxBuffer + AES128LENGTHINBYTES); //Trigger is coded inside aes function after key expansion
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back ciphertext via UART
				break;

			/////Software crypto with countermeasures //////
			//Software DES - encrypt with Random S-box order
			case CMD_SWDES_ENC_RND_SBOX:
				get_bytes(8, rxBuffer); // Receive DES plaintext
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				desRandomSboxes(keyDES, rxBuffer, ENCRYPT); // Perform software DES encryption
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_bytes(8, rxBuffer); // Transmit back ciphertext via UART
				break;
			//Software DES - encrypt with Random delays
			case CMD_SWDES_ENC_RND_DELAYS:
				get_bytes(8, rxBuffer); // Receive DES plaintext
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				desRandomDelays(keyDES, rxBuffer, ENCRYPT,2); // Perform software DES encryption
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_bytes(8, rxBuffer); // Transmit back ciphertext via UART
				break;
			//Software masked AES128 - encrypt
			case CMD_SWAES128_ENC_MASKED:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				mAES128_ECB_encrypt(rxBuffer, keyAES, rxBuffer + AES128LENGTHINBYTES); //Trigger is coded inside aes function, includes masking process
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back ciphertext via UART
				break;
			//Software masked AES128 - decrypt
			case CMD_SWAES128_DEC_MASKED:
				get_bytes(16, rxBuffer); // Receive AES ciphertext
				mAES128_ECB_decrypt(rxBuffer, keyAES, rxBuffer + AES128LENGTHINBYTES); //Trigger is coded inside aes function, includes masking process
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back plaintext via UART
				break;
			//Software AES128 - random delays
			case CMD_SWAES128_ENC_RNDDELAYS:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				AES128_ECB_encrypt_rndDelays(rxBuffer, keyAES, rxBuffer + AES128LENGTHINBYTES); //Trigger is coded inside aes function, includes masking process
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back ciphertext via UART
				break;
			//Software AES128 - random sbox order
			case CMD_SWAES128_ENC_RNDSBOX:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				AES128_ECB_encrypt_rndSbox(rxBuffer, keyAES, rxBuffer + AES128LENGTHINBYTES); //Trigger is coded inside aes function, includes masking process
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back ciphertext via UART
				break;

			// RSA-CRT 1024bit decryption, textbook style (non-time constant)
			case CMD_RSACRT1024_DEC:
				if (cmd == 0) { //Legacy support of RLV protocol
					get_char(&cmd);
				}
				get_char(&tmp); // Receive payload length, expect MSByte first
				payload_len |= tmp;
				payload_len <<= 8;
				get_char(&tmp);
				payload_len |= tmp;
				//Receive payload_len bytes from the USART (truncating plaintext length if too long)
				if (payload_len > RXBUFFERLENGTH) {
					payload_len = RXBUFFERLENGTH;
				}
				get_bytes(payload_len, rxBuffer);
				input_cipher_text(payload_len); // Fill the cipher text buffer "c" with incoming data bytes, assuming MSByte first and 32-bit alignment
				rsa_crt_decrypt(); // Start RSA CRT procedure, Trigger signal toggling contained within the call
				send_clear_text(); // Send content of clear text buffer "m" back to Host PC, MSByte first 32-bit alignment
				break;

			//Software AES(Ttables implementation) - encrypt
			case CMD_SWAES128TTABLES_ENC:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				rijndaelSetupEncrypt(keyScheduleAES, keyAES, 128); //Prepare AES key schedule
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				rijndaelEncrypt(keyScheduleAES, 10, rxBuffer, rxBuffer + AES128LENGTHINBYTES); // Perform software AES encryption
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back ciphertext via UART
				break;

			//Software AES(Ttables implementation) - decrypt
			case CMD_SWAES128TTABLES_DEC:
				get_bytes(16, rxBuffer); // Receive AES plaintext
				rijndaelSetupDecrypt(keyScheduleAES, keyAES, 128); //Prepare AES key schedule
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				rijndaelDecrypt(keyScheduleAES, 10, rxBuffer, rxBuffer + AES128LENGTHINBYTES); // Perform software AES decryption
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back plaintext via UART
				break;

			//Software RSA-512 SFM commands
			case CMD_RSASFM_GET_HARDCODED_KEY:
				rsa_sfm_send_hardcoded_key();
				break;
			case CMD_RSASFM_SET_D:
				get_char(&tmp);		// Receive payload length, expect MSByte first
				payload_len |= tmp;
				payload_len <<= 8;
				get_char(&tmp);
				payload_len |= tmp;
				//Receive payload_len bytes from the USART (truncating plaintext length if too long)
				if(payload_len>RXBUFFERLENGTH){
					payload_len=RXBUFFERLENGTH;
				}
				get_bytes(payload_len,rxBuffer);
				input_external_exponent(payload_len);
				send_char(cmd);
				break;
			case CMD_RSASFM_DEC:
				get_char(&tmp);		// Receive payload length, expect MSByte first
				payload_len |= tmp;
				payload_len <<= 8;
				get_char(&tmp);
				payload_len |= tmp;
				//Receive payload_len bytes from the USART (truncating plaintext length if too long)
				if(payload_len>RXBUFFERLENGTH){
					payload_len=RXBUFFERLENGTH;
				}
				get_bytes(payload_len,rxBuffer);
				input_cipher_text(payload_len);	// Fill the cipher text buffer "c" with incoming data bytes, assuming MSByte first and 32-bit alignment
				rsa_sfm_decrypt();
				send_clear_text();
				break;
			case CMD_RSASFM_SET_KEY_GENERATION_METHOD:
				get_char(&tmp);
				rsa_sfm_set_key_generation_method(tmp);
				send_char(tmp);
				break;
			case CMD_RSASFM_SET_IMPLEMENTATION:
				get_char(&tmp);
				rsa_sfm_set_implementation_method(tmp);
				send_char(tmp);
				break;

			/////////Hardware crypto commands/////////
#ifndef HW_CRYPTO_PRESENT
			//Fallback for Pinata boards without HW crypto processor: board will reply zeroes without any trigger instead of BADCMD to quickly identify the issue
			case CMD_HWAES128_ENC:
			case CMD_HWAES128_DEC:
			case CMD_HWAES256_ENC:
			case CMD_HWAES256_DEC:
				get_bytes(16, rxBuffer);
				//HW crypto is not supported: send zeroes back
				send_bytes(16, zeros);
				break;
			case CMD_HWDES_ENC:
			case CMD_HWDES_DEC:
			case CMD_HWTDES_ENC:
			case CMD_HWTDES_DEC:
				get_bytes(8, rxBuffer);
				//HW crypto is not supported: send zeroes back
				send_bytes(8, zeros);
				break;
			case CMD_SHA1_HASH:
				get_bytes(sizeof(uint32_t), rxBuffer);
				get_bytes(16, rxBuffer);
				//HW hashing is not supported: send zeroes back
				send_bytes(20, zeros);
				break;
			case CMD_HMAC_SHA1:
				get_bytes(sizeof(uint32_t), rxBuffer);
				get_bytes(20, rxBuffer);
				//HW hashing is not supported: send zeroes back
				send_bytes(20, zeros);
				break;
#endif

#ifdef HW_CRYPTO_PRESENT
			//Hardware AES128 - encrypt
			case CMD_HWAES128_ENC:
				get_bytes(16, rxBuffer);
				//Trigger pin handling moved to CRYP_AES_ECB function
				cryptoCompletedOK = CRYP_AES_ECB(MODE_ENCRYPT, keyAES, 128,	rxBuffer, (uint32_t) AES128LENGTHINBYTES, rxBuffer + AES128LENGTHINBYTES);
				if (cryptoCompletedOK == SUCCESS) {
					send_bytes(16, rxBuffer + AES128LENGTHINBYTES);
				} else {
					send_bytes(16, zeros);
				}
				break;

			//Hardware AES128 - decrypt
			case CMD_HWAES128_DEC:
				get_bytes(16, rxBuffer);
				//Trigger pin handling moved to CRYP_AES_ECB function
				cryptoCompletedOK = CRYP_AES_ECB(MODE_DECRYPT, keyAES, 128,	rxBuffer, (uint32_t) AES128LENGTHINBYTES, rxBuffer + AES128LENGTHINBYTES);
				if (cryptoCompletedOK == SUCCESS) {
					send_bytes(16, rxBuffer + AES128LENGTHINBYTES);
				} else {
					send_bytes(16, zeros);
				}
				break;

			//Hardware AES256 - encrypt
			case CMD_HWAES256_ENC:
				get_bytes(16, rxBuffer);
				//Trigger pin handling moved to CRYP_AES_ECB function
				cryptoCompletedOK = CRYP_AES_ECB(MODE_ENCRYPT, keyAES256, 256,	rxBuffer, (uint32_t) 16, rxBuffer + 16);
				if (cryptoCompletedOK == SUCCESS) {
					send_bytes(16, rxBuffer + 16);
				} else {
					send_bytes(16, zeros);
				}
				break;

			//Hardware AES256 - decrypt
			case CMD_HWAES256_DEC:
				get_bytes(16, rxBuffer);
				//Trigger pin handling moved to CRYP_AES_ECB function
				cryptoCompletedOK = CRYP_AES_ECB(MODE_DECRYPT, keyAES256, 256,	rxBuffer, (uint32_t) 16, rxBuffer + 16);
				if (cryptoCompletedOK == SUCCESS) {
					send_bytes(16, rxBuffer + 16);
				} else {
					send_bytes(16, zeros);
				}
				break;

			//Hardware DES - encrypt
			case CMD_HWDES_ENC:
				get_bytes(8, rxBuffer);
				//Trigger pin handling moved to CRYP_DES_ECB function
				cryptoCompletedOK=CRYP_DES_ECB(MODE_ENCRYPT,keyDES,rxBuffer,(uint32_t)8,rxBuffer+8);
				if (cryptoCompletedOK == SUCCESS) {
					send_bytes(8, rxBuffer + 8);
				} else {
					send_bytes(8, zeros);
				}
				break;

			//Hardware DES - decrypt
			case CMD_HWDES_DEC:
				get_bytes(8, rxBuffer);
				//Trigger pin handling moved to CRYP_DES_ECB function
				cryptoCompletedOK=CRYP_DES_ECB(MODE_DECRYPT,keyDES,rxBuffer,(uint32_t)8,rxBuffer+8);
				if (cryptoCompletedOK == SUCCESS) {
					send_bytes(8, rxBuffer + 8);
				} else {
					send_bytes(8, zeros);
				}
				break;

			//Hardware TDES - encrypt
			case CMD_HWTDES_ENC:
				get_bytes(8, rxBuffer);
				//Trigger pin handling moved to CRYP_DES_ECB function
				cryptoCompletedOK=CRYP_TDES_ECB(MODE_ENCRYPT,keyTDES,rxBuffer,(uint32_t)8,rxBuffer+8);
				if (cryptoCompletedOK == SUCCESS) {
					send_bytes(8, rxBuffer + 8);
				} else {
					send_bytes(8, zeros);
				}
				break;

			//Hardware TDES - decrypt
			case CMD_HWTDES_DEC:
				get_bytes(8, rxBuffer);
				//Trigger pin handling moved to CRYP_DES_ECB function
				cryptoCompletedOK=CRYP_TDES_ECB(MODE_DECRYPT,keyTDES,rxBuffer,(uint32_t)8,rxBuffer+8);
				if (cryptoCompletedOK == SUCCESS) {
					send_bytes(8, rxBuffer + 8);
				} else {
					send_bytes(8, zeros);
				}
				break;


				//Hardware HMAC SHA1 (key is the same as the TDES key)
			case CMD_HMAC_SHA1:
				{
				get_bytes(sizeof(uint32_t), rxBuffer);
				uint32_t rxBuffer32 = (uint32_t)rxBuffer;
				uint32_t iterations = __REV(*(uint32_t*)rxBuffer32);

				get_bytes(20, rxBuffer);
				RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_HASH, ENABLE);
				// 24 byte key used is the same as the TDES key!!
				cryptoCompletedOK = HMAC_SHA1(keyTDES, sizeof(keyTDES), rxBuffer+sizeof(uint32_t), 20, rxBuffer+24, iterations);
				RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_HASH, DISABLE);

				if (cryptoCompletedOK == SUCCESS) {
					send_bytes(20, rxBuffer+24);
				} else {
					send_bytes(20, zeros);
				}
				}
				break;

				//Hardware SHA1
			case CMD_SHA1_HASH:
				{
				get_bytes(sizeof(uint32_t), rxBuffer);
				uint32_t rxBuffer32 = (uint32_t)rxBuffer;
				uint32_t iterations = __REV(*(uint32_t*)rxBuffer32);

				get_bytes(16, rxBuffer);

				RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_HASH, ENABLE);
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				cryptoCompletedOK = HASH_SHA1(rxBuffer+sizeof(uint32_t), 16, rxBuffer+20, iterations);
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_HASH, DISABLE);

				if (cryptoCompletedOK == SUCCESS) {
					send_bytes(20, rxBuffer+20);
				} else {
					send_bytes(20, zeros);
				}
				}
				break;

#endif
			//////Cryptographic keys management//////

			//TDES key change
			case CMD_TDES_KEYCHANGE:
				get_bytes(24, rxBuffer);
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				for (i = 0; i < 24; i++) keyTDES[i] = rxBuffer[i];
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_bytes(24,keyTDES);
				break;

			//DES key change
			case CMD_DES_KEYCHANGE:
				get_bytes(8, rxBuffer);
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				for (i = 0; i < 8; i++) keyDES[i] = rxBuffer[i];
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_bytes(8,keyDES);
				break;

			//AES128 key change
			case CMD_AES128_KEYCHANGE:
				get_bytes(16, rxBuffer);
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				for (i = 0; i < 16; i++) keyAES[i] = rxBuffer[i];
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_bytes(16,keyAES);
				break;

			//AES256 key change
			case CMD_AES256_KEYCHANGE:
				get_bytes(32, rxBuffer);
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				for (i = 0; i < 32; i++) keyAES256[i] = rxBuffer[i];
				//Recompute again aes256 key schedule
				aes256_init(&ctx,keyAES256); //Prepare AES key schedule for software AES256
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_bytes(32,keyAES256);
				break;

			//Password change (4 bytes long, used for password check commands & FI)
			case CMD_PWD_CHANGE:
				authenticated=0;
				get_bytes(4, rxBuffer);
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				for (i = 0; i < 4; i++) password[i] = rxBuffer[i];
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_bytes(4,password);
				break;

			//SM4 key change
			case CMD_SM4_KEYCHANGE:
				get_bytes(16, rxBuffer);
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				for (i = 0; i < 16; i++) keySM4[i] = rxBuffer[i];
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_bytes(16,keySM4);
				break;


			/////Template analysis commands/////

			//Software key copy (byte-wise)
			case CMD_SOFTWARE_KEY_COPY:
				get_bytes(16, rxBuffer); // Receive AES128 key (16 byte)
				for (i = 0; i < 16; i++) keyLoadingAES[i] = 0; //Initialize key array
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on PC2 for key loading
				busyWait1=0;
				while (busyWait1 < 500) busyWait1++; //For avoiding ringing on GPIO toggling

				//Key copy, byte-wise, with a delay between key bytes copy to make it even more evident where key copy happens
				keyLoadingAES[0] = rxBuffer[0];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[1] = rxBuffer[1];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[2] = rxBuffer[2];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[3] = rxBuffer[3];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[4] = rxBuffer[4];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[5] = rxBuffer[5];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[6] = rxBuffer[6];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[7] = rxBuffer[7];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[8] = rxBuffer[8];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[9] = rxBuffer[9];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[10] = rxBuffer[10];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[11] = rxBuffer[11];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[12] = rxBuffer[12];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[13] = rxBuffer[13];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[14] = rxBuffer[14];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				keyLoadingAES[15] = rxBuffer[15];
				busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;busyWait1++;
				//End of key-copy

				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off PC2 end of key loading
				send_bytes(16, keyLoadingAES); // Transmit back loaded key via UART
				break;


			/////Fault Injection commands/////

			//Infinite loop for FI (has a NOP sled after the infinite loop)
			case CMD_INFINITE_FI_LOOP:
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				while (1) {
					oled_sendchar(".");
					busyWait1 = 0;
					while (busyWait1 < 84459459) busyWait1++; //Roughly 0.5 seconds @ 168MHz
					oled_sendchar(" ");
					busyWait1 = 0;
					while (busyWait1 < 84459459) busyWait1++; //Roughly 0.5 seconds @ 168MHz
				}
				//Small NOP sled
				__asm __volatile__("mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						);
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_char('G');send_char('l');send_char('i');send_char('t');send_char('c');send_char('e');send_char('d');send_char('!');
				break;

			//Loop test command for FI
			case CMD_LOOP_TEST_FI: {
				volatile int upCounter = 0;
				payload_len = 0;
				get_char(&tmp); // Receive payload length, expect MSByte first, 16bit counter max
				payload_len |= tmp;
				payload_len <<= 8;
				get_char(&tmp);
				payload_len |= tmp;
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				while (payload_len) {
					payload_len--;
					upCounter++;
				}
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_char(0xA5);
				send_char((payload_len>>8)&0x000000FF); //MSB first
				send_char( payload_len    &0x000000FF);
				send_char((upCounter>>8)  &0x000000FF);
				send_char( upCounter      &0x000000FF);
				send_char(0xA5);
				break;
			}

			//Password check - single check for Fault Injection
			case CMD_SINGLE_PWD_CHECK_FI: {
				volatile int charsOK = 0;
				authenticated = 0;
				get_bytes(4, rxBuffer);
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				//Small delay to have a bit of time between trigger to glitch
				__asm __volatile__("mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						);
				for (i = 0;i < 4; i++) {
					if (rxBuffer[i] == password[i]) {
						charsOK = charsOK + 1;
					}
				}
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				if (charsOK == 4) {
					authenticated=1;
					send_char(0x90);send_char(0x00);
				} else {
					send_char(0x69);send_char(0x86);
				}
				break;
			}

			//Password check - double check for Fault Injection
			case CMD_DOUBLE_PWD_CHECK_FI: {
				volatile int charsOK = 0;
				authenticated = 0;
				get_bytes(4, rxBuffer);
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				//Small delay to have a bit of time between trigger to glitch
				__asm __volatile__("mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						"mov r0,r0\n"
						);
				for (i = 0; i < 4; i++) {
					if (rxBuffer[i] == password[i]) {
						charsOK = charsOK + 1;
					}
				}
				if (charsOK == 4) {
					//Spacing to avoid that a single glitch does not bypass the two checks
					__asm __volatile__("mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							"mov r0,r0\n"
							);

					if ((*(uint32_t*)(rxBuffer))^(*(uint32_t*)(password)) == 0) { //Second check is a different one (uses a XOR of the 2 passwords of 4 chars)
						authenticated=1;
						send_char(0x90);send_char(0x00);
					} else {
						send_char(0x69);send_char(0x86);
					}
				} else {
					send_char(0x69);send_char(0x00);
				}
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				break;
			}

			//Software DES encryption with a double check (for Advanced FI DFA scenarios)
			case CMD_SWDES_ENCRYPT_DOUBLECHECK:
				get_bytes(8, rxBuffer); // Receive DES plaintext
				//Copy the plaintext twice to perform two encryptions
				for(i=0;i<8;i++){
					rxBuffer[8+i]=rxBuffer[i];
				}
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				des(keyDES, rxBuffer, ENCRYPT); // Perform software DES encryption
				des(keyDES, rxBuffer+8, ENCRYPT); // Perform second software DES encryption
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				//Compare the two encrypted texts; if same, transmit them, otherwise send nothing
				if(memcmp(rxBuffer,rxBuffer+8,8)==0){
					send_bytes(8, rxBuffer); // Transmit back ciphertext via UART
				}
				else{
					//Do not transmit anything
				}
				break;

			//AES128 SW encryption with a double check (for Advanced FI DFA scenarios)
			case CMD_SWAES128_ENCRYPT_DOUBLECHECK:{
				volatile uint8_t decrypted_input[16];
				get_bytes(16, rxBuffer); // Receive AES plaintext
				rijndaelSetupDecrypt(keyScheduleAES, keyAES, 128); //Prepare T-Tables AES key schedule for double check

				//Encrypt with textbook AES128 for easing the glitch
				AES128_ECB_encrypt(rxBuffer, keyAES, rxBuffer + AES128LENGTHINBYTES); //Trigger is coded inside aes function after key expansion
				//Decrypt with T-Tables AES for speed
				rijndaelDecrypt(keyScheduleAES, 10, rxBuffer + AES128LENGTHINBYTES, decrypted_input); // Perform software AES decryption

				//If decrypted txt is the same as the original txt, send the ciphertext; otherwise send nothing
				if(memcmp(decrypted_input, rxBuffer,16)==0){
					send_bytes(16, rxBuffer + AES128LENGTHINBYTES); // Transmit back ciphertext via UART
				}
				else{
					//Do not transmit anything
				}
				break;
			}

			///// TRNG //////
			case CMD_GET_RANDOM_FROM_TRNG:{
				volatile uint32_t randomNumber;
				RNG_Enable();
				//Get a random number
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				while (RNG_GetFlagStatus(RNG_FLAG_DRDY) == RESET){}
				randomNumber=RNG_GetRandomNumber();
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				RNG_Disable();
				send_char((randomNumber>>24)&0x000000FF); //MSB first
				send_char((randomNumber>>16)&0x000000FF);
				send_char((randomNumber>> 8)&0x000000FF);
				send_char( randomNumber     &0x000000FF);
				break;
				}

			/////Test commands/////
			//Test command for the OLED screen
			case CMD_OLED_TEST:
				oled_reset();
				oled_clear();
				oled_sendchar('H');
				oled_sendchar('i');
				oled_sendchar(' ');
				oled_sendchar('!');
				break;

			//Send stm32f4 chip UID via I/O interface
			case CMD_UID_VIA_IO:
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				uint32_t uidBlock1 = STM32F4ID[0];
				uint32_t uidBlock2 = STM32F4ID[1];
				uint32_t uidBlock3 = STM32F4ID[2];
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				send_char((uidBlock1>>24)&0x000000FF); //MSB first
				send_char((uidBlock1>>16)&0x000000FF);
				send_char((uidBlock1>> 8)&0x000000FF);
				send_char( uidBlock1     &0x000000FF);
				send_char((uidBlock2>>24)&0x000000FF); //MSB first
				send_char((uidBlock2>>16)&0x000000FF);
				send_char((uidBlock2>> 8)&0x000000FF);
				send_char( uidBlock2     &0x000000FF);
				send_char((uidBlock3>>24)&0x000000FF); //MSB first
				send_char((uidBlock3>>16)&0x000000FF);
				send_char((uidBlock3>> 8)&0x000000FF);
				send_char( uidBlock3     &0x000000FF);
				break;

			//Code version command: returns code version string (8 bytes, "Ver x.x" ASCII encoded) on code revision 2.0 or higher, "BadCmd" on code revision 1.0
			case CMD_GET_CODE_REV:
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				send_bytes(8, codeVersion);
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				break;

			//Change clock speed on-the-fly and restart peripherals; predefined speeds are 16, 30, 84 and 168MHz. If parameter is not in this list, speed will be set to 168MHz by default.
			case CMD_CHANGE_CLK_SPEED:
				get_char(&tmp);
				setClockSpeed(tmp);
				send_char(clockspeed);
				break;

			//Change clock source to external. The argument specifies whether the clock is used directly (value = 0), or through the PLL (value != 0)
			case CMD_SET_EXTERNAL_CLOCK:
				get_char(&tmp);
				setExternalClock(tmp);
				send_char(clockSource);
				break;

			//Unknown command byte: return error or 4 times (0x90 0x00) if board was glitched during boot
			default:
				GPIOC->BSRRL = GPIO_Pin_2; //Trigger on
				if (glitchedBoot) {
					for (i = 0; i < 4; i++){
						send_char(0x90);
						send_char(0x00);
					}
				}
				else if(authenticated){ //This will be the answer if the authenticated flag is set != 0
					send_char(0xC0);
					send_char(0xBF);
					send_char(0xEF);
					send_char(0xEE);
					send_char(0xBA);
					send_char(0xDB);
					send_char(0xAB);
					send_char(0xEE);
				}
				else{
					send_bytes(8, cmdByteIsWrong);
				}
				GPIOC->BSRRH = GPIO_Pin_2; //Trigger off
				break;
		}
	}

	//If we glitch the board out of the main loop, it will end up here (target will loop forever sending bytes 0xFA, 0xCC)
	while (1) {
		send_bytes(2, glitched);
	}
	return 0;
}

////////////////////////////////////////////////////
//            END OF MAIN FUNCTION                //
////////////////////////////////////////////////////



///////////////////////////
//FUNCTION IMPLEMENTATION//
///////////////////////////

//init(): system initialization, pin configuration and system tick configuration for timers
void init() {
	/* STM32F4 GPIO ports */

	GPIO_InitTypeDef GPPortA,GPPortC,GPPortF, GPPortH;

	//PA9: IO configuration pin. Jumper between VBUS, PA9
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOA, ENABLE);
	GPPortA.GPIO_Pin =  GPIO_Pin_9;
	GPPortA.GPIO_Mode = GPIO_Mode_IN;
	GPPortA.GPIO_OType = GPIO_OType_PP;
	GPPortA.GPIO_Speed = GPIO_Speed_50MHz;
	GPPortA.GPIO_PuPd = GPIO_PuPd_DOWN;
	GPIO_Init(GPIOA, &GPPortA);

	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOF, ENABLE);
	GPPortF.GPIO_Pin = GPIO_Pin_2 | GPIO_Pin_4 | GPIO_Pin_5 | GPIO_Pin_6 | GPIO_Pin_8| GPIO_Pin_9;
	GPPortF.GPIO_Mode = GPIO_Mode_OUT;
	GPPortF.GPIO_OType = GPIO_OType_PP;
	GPPortF.GPIO_Speed = GPIO_Speed_100MHz;
	GPPortF.GPIO_PuPd = GPIO_PuPd_NOPULL;
	GPIO_Init(GPIOF, &GPPortF);

	//DEFAULT TRIGGER PIN IS PC2; utility functions defined in stm32f4xx_gpio.c in functions set_trigger() and clear_trigger() functions
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOC, ENABLE);
	GPPortC.GPIO_Pin = GPIO_Pin_1 | GPIO_Pin_2;
	GPPortC.GPIO_Mode = GPIO_Mode_OUT;
	GPPortC.GPIO_OType = GPIO_OType_PP;
	GPPortC.GPIO_Speed = GPIO_Speed_100MHz;
	GPPortC.GPIO_PuPd = GPIO_PuPd_NOPULL;
	GPIO_Init(GPIOC, &GPPortC);

	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOH, ENABLE);
	GPPortH.GPIO_Pin = GPIO_Pin_2 | GPIO_Pin_3;
	GPPortH.GPIO_Mode = GPIO_Mode_OUT;
	GPPortH.GPIO_OType = GPIO_OType_PP;
	GPPortH.GPIO_Speed = GPIO_Speed_100MHz;
	GPPortH.GPIO_PuPd = GPIO_PuPd_NOPULL;
	GPIO_Init(GPIOH, &GPPortH);
	/* Setup SysTick or crash */
	if (SysTick_Config(SystemCoreClock / 1000)) {
		CrashGracefully();
	}

	/* Enable CRYP clock for hardware crypto; disable this for STM32F407IGT6 by commenting HW_CRYPTO_PRESENT in main.h*/
#ifdef HW_CRYPTO_PRESENT
	RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_CRYP, ENABLE);
#endif

	/* Setup USB virtual COM port if enabled; otherwise disable as it generates noise in the power lines */
	usbSerialEnabled = GPIO_ReadInputDataBit(GPIOA, GPIO_Pin_9);
	if (usbSerialEnabled) {
	USBD_Init(&USB_OTG_dev,
			USB_OTG_FS_CORE_ID,
			&USR_desc,
			&USBD_CDC_cb,
			&USR_cb);
	}

}

//usart_init: configures the usart3 interface
void usart_init(void) {
	/* USART3 configured as follows:
	 - BaudRate = 115200 baud
	 - Word Length = 8 Bits
	 - One Stop Bit
	 - No parity
	 - Hardware flow control disabled (RTS and CTS signals)
	 - Receive and transmit enabled
	 - PC10 TX pin, PC11 RX pin
	 */
	GPIO_InitTypeDef GPIO_InitStructure;
	USART_InitTypeDef USART_InitStructure;

	/* Enable GPIO clock */
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOC, ENABLE);

	/* Enable UART clock */
	RCC_APB1PeriphClockCmd(RCC_APB1Periph_USART3, ENABLE);

	/* Connect PXx to USARTx_Tx*/
	GPIO_PinAFConfig(GPIOC, GPIO_PinSource10, GPIO_AF_USART3);

	/* Connect PXx to USARTx_Rx*/
	GPIO_PinAFConfig(GPIOC, GPIO_PinSource11, GPIO_AF_USART3);

	/* Configure USART Tx as alternate function  */
	GPIO_InitStructure.GPIO_OType = GPIO_OType_PP;
	GPIO_InitStructure.GPIO_PuPd = GPIO_PuPd_UP;
	GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AF;

	GPIO_InitStructure.GPIO_Pin = GPIO_Pin_10;
	GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
	GPIO_Init(GPIOC, &GPIO_InitStructure);

	/* Configure USART Rx as alternate function  */
	GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AF;
	GPIO_InitStructure.GPIO_Pin = GPIO_Pin_11;
	GPIO_Init(GPIOC, &GPIO_InitStructure);

	USART_InitStructure.USART_BaudRate = 115200;
	USART_InitStructure.USART_WordLength = USART_WordLength_8b;
	USART_InitStructure.USART_StopBits = USART_StopBits_1;
	USART_InitStructure.USART_Parity = USART_Parity_No;
	USART_InitStructure.USART_HardwareFlowControl =
			USART_HardwareFlowControl_None;
	USART_InitStructure.USART_Mode = USART_Mode_Rx | USART_Mode_Tx;

	/* USART configuration */
	USART_Init(USART3, &USART_InitStructure);

	/* Enable USART */
	USART_Cmd(USART3, ENABLE);

}

//oled_init: configures the SPI2 interface with associated GPIO pins for SS, data/cmd# and reset lines
void oled_init(){
	/* Pins used by SPI2 & GPIOs for SSD1306 OLED display
	 * PB13 = SCK == blue wire to SSD1306 OLED display
	 * PB14 = MISO == nc
	 * PB15 = MOSI == green wire to SSD1306 OLED display
	 * PF4  = SS == white wire to SSD1306 OLED display
	 * PF5 = data/cmd# line of SSD1306 OLED display == yellow wire to SSD1306 OLED display
	 * PF8 = reset line of SSD1306 OLED display == orange wire to SSD1306 OLED display
	 *
	 */
	//Enable clock for GPIO pins for SPI
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOB, ENABLE);

	GPIO_InitTypeDef GPIO_InitStruct;
	GPIO_InitStruct.GPIO_Pin = GPIO_Pin_13 | GPIO_Pin_14|GPIO_Pin_15;
	GPIO_InitStruct.GPIO_Mode = GPIO_Mode_AF;
	GPIO_InitStruct.GPIO_OType = GPIO_OType_PP;
	GPIO_InitStruct.GPIO_Speed = GPIO_Speed_100MHz;
	GPIO_InitStruct.GPIO_PuPd = GPIO_PuPd_UP;
	GPIO_Init(GPIOB, &GPIO_InitStruct);

	RCC_APB1PeriphClockCmd(RCC_APB1Periph_SPI2, ENABLE);
	SPI_InitTypeDef SPI_InitTypeDefStruct;

	SPI_InitTypeDefStruct.SPI_BaudRatePrescaler = SPI_BaudRatePrescaler_2; //APB1 bus speed=(168/4)=42MHz; SPI speed with prescaler 2-> (42/4)=21MHz
	SPI_InitTypeDefStruct.SPI_Direction = SPI_Direction_1Line_Tx;
	SPI_InitTypeDefStruct.SPI_Mode = SPI_Mode_Master;
	SPI_InitTypeDefStruct.SPI_DataSize = SPI_DataSize_8b;
	SPI_InitTypeDefStruct.SPI_NSS = SPI_NSS_Soft;
	SPI_InitTypeDefStruct.SPI_FirstBit = SPI_FirstBit_MSB;
	SPI_InitTypeDefStruct.SPI_CPOL = SPI_CPOL_Low;
	SPI_InitTypeDefStruct.SPI_CPHA = SPI_CPHA_1Edge;
	// connect SPI1 pins to SPI alternate function
	GPIO_PinAFConfig(GPIOB, GPIO_PinSource13 , GPIO_AF_SPI2);
	GPIO_PinAFConfig(GPIOB, GPIO_PinSource14, GPIO_AF_SPI2);
	GPIO_PinAFConfig(GPIOB, GPIO_PinSource15 , GPIO_AF_SPI2);
	SPI_Init(SPI2, &SPI_InitTypeDefStruct);
	SPI_Cmd(SPI2, ENABLE);

	//SPI interface and GPIO pins are configured: reset the OLED display
	oled_reset();
}

//////Interrupt Handlers/////////

void SysTick_Handler(void) {
	ticker++;
	if (downTicker > 0) {
		downTicker--;
	}
}
//Debugging: Hard error management
void HardFault_Handler(void) {CrashGracefully();}
void MemManage_Handler(void) {CrashGracefully();}
void BusFault_Handler(void) {CrashGracefully();}
void UsageFault_Handler(void) {CrashGracefully();}


////////I/O utility functions (UART, serial over USB)////////////

//System functions: disable/enable

//Wrapper functions for UART / serial over USB
//get_bytes: get an amount of nbytes bytes from IO interface into byte array ba
void get_bytes(uint32_t nbytes, uint8_t* ba) {
	if (usbSerialEnabled) {
		get_bytes_usb(nbytes,ba);
	} else {
		get_bytes_uart(nbytes,ba);
	}
}
//send_bytes: send an amount of nbytes bytes from byte array ba via IO interface
void send_bytes(uint32_t nbytes, uint8_t* ba) {
	if (usbSerialEnabled) {
		send_bytes_usb(nbytes,ba);
	} else {
		send_bytes_uart(nbytes,ba);
	}
}
//get_char: receive a byte via IO interface
void get_char(uint8_t *ch) {
	if (usbSerialEnabled) {
		get_char_usb(ch);
	} else {
		get_char_uart(ch);
	}
}
//send_char: send a byte via IO interface
void send_char(uint8_t ch) {
	if (usbSerialEnabled) {
		send_char_usb(ch);
	} else {
		send_char_uart(ch);
	}
}

//UART IO
//get_bytes: get an amount of nbytes bytes from uart into byte array ba
void get_bytes_uart(uint32_t nbytes, uint8_t* ba) {
	int i;
	for (i = 0; i < nbytes; i++) {
		while ((USART3->SR & USART_SR_RXNE) == 0);

		ba[i] = (uint8_t) USART_ReceiveData(USART3);
	}
}
//send_bytes: send an amount of nbytes bytes from byte array ba via uart
void send_bytes_uart(uint32_t nbytes, uint8_t* ba) {
	int i;
	for (i = 0; i < nbytes; i++) {
		while (!(USART3->SR & USART_SR_TXE));

		USART_SendData(USART3, ba[i]);
	}
}
//get_char: receive a byte via uart
void get_char_uart(uint8_t *ch) {
	while ((USART3->SR & USART_SR_RXNE) == 0);

	*ch = (uint8_t) USART_ReceiveData(USART3);
}
//send_char: send a byte via uart
void send_char_uart(uint8_t ch) {
	while (!(USART3->SR & USART_SR_TXE));

	USART_SendData(USART3, ch);
}

//Serial over USB communication functions
//get_bytes: get an amount of nbytes bytes into byte array ba via usb com port
void get_bytes_usb(uint32_t nbytes, uint8_t* ba) {
	int i;
	uint8_t tmp;
	for (i = 0; i < nbytes; i++) {
		tmp = 0;
		while (!VCP_get_char(&tmp));

		ba[i] = tmp;
	}
}
//send_bytes: send an amount of nbytes bytes from byte array ba via usb com port
void send_bytes_usb(uint32_t nbytes, uint8_t* ba) {
	int i;
	for (i = 0; i < nbytes; i++) {
		VCP_put_char(ba[i]);
	}

}
//get_char: receive a byte over usb com port
void get_char_usb(uint8_t *ch) {
	uint8_t tmp=0;
	while (!VCP_get_char(&tmp));

	*ch = tmp;
}
//send_char: send a byte over usb com port
void send_char_usb(uint8_t ch) {
	VCP_put_char(ch);
}

//USB IRQ handlers
void OTG_FS_IRQHandler(void)
{
	if (usbSerialEnabled) {
		USBD_OTG_ISR_Handler (&USB_OTG_dev);
	}
}

void OTG_FS_WKUP_IRQHandler(void)
{
	if (usbSerialEnabled) {
		if (USB_OTG_dev.cfg.low_power) {
			*(uint32_t *)(0xE000ED10) &= 0xFFFFFFF9;
			SystemInit();
			USB_OTG_UngateClock(&USB_OTG_dev);
		}
		EXTI_ClearITPendingBit(EXTI_Line18);
	}
}


/////Debug functions for your own code (e.g. RSA implementations)////////
void readByteFromInputBuffer(uint8_t *ch) {
	*ch = rxBuffer[charIdx]; //charIdx is a global variable, defined in rsacrt.c/.h
	charIdx++;
}
void CrashGracefully(void) {
	//Put anything you would like here to happen on a hard fault
	GPIOF->BSRRH = GPIO_Pin_6; //Example handler: PF6 enabled
}

/////Clock handling functions////////

//// Functions to change on-the-fly the clockspeed; supported speeds: 30, 84 and 168MHz ////
void setClockSpeed(uint8_t speed) {
	uint16_t timeout;

	// Enable HSI clock and switch to it while we mess with the PLLs
	RCC->CR |= RCC_CR_HSION;
	timeout = 0xFFFF;
	while (!(RCC->CR & RCC_CR_HSIRDY) && timeout--);
	RCC->CFGR = (RCC->CFGR & ~(RCC_CFGR_SW)) | RCC_CFGR_SW_HSI;

	//Disable PLL, reconfigure settings, enable again PLL
	RCC->CR &= ~RCC_CR_PLLON;
	switch (speed) {	//PLLs config: HSE as ext. clk source, plls values for M,N,P,Q
		case 30:
			RCC_PLLConfig(RCC_PLLSource_HSE, 8, 240, 8, 5); clockspeed=30;
			break;
		case 84:
			RCC_PLLConfig(RCC_PLLSource_HSE, 8, 336, 4, 7); clockspeed=84;
			break;
		case 168:
		default: //If incorrect value, we also set speed to 168MHz and return that clockspeed is 168MHz
			RCC_PLLConfig(RCC_PLLSource_HSE, 8, 336, 2, 7);clockspeed=168;
			break;
	}
	RCC->CR |= RCC_CR_PLLON;

	//Wait for PLL and switch back to it
	timeout = 0xFFFF;
	while ((RCC->CR & RCC_CR_PLLRDY) && timeout--);
	RCC->CFGR = (RCC->CFGR & ~(RCC_CFGR_SW)) | RCC_CFGR_SW_PLL;

	//Update system core clockspeed for peripherals to set configurations properly
	SystemCoreClockUpdate();

	//Reinitialize peripherals because changing the RCC_PLLConfig has messed up all the clocking
	init();
	if (!usbSerialEnabled) {
		usart_init();
	}

	clockSource = (RCC->CFGR & RCC_CFGR_SWS) >> 2;

	//Disable SysTick interrupt to avoid spikes every 1ms
	SysTick->CTRL = SysTick_CTRL_CLKSOURCE_Msk | SysTick_CTRL_ENABLE_Msk;
}

//switch clock to external clock supply
void setExternalClock(uint8_t source) {
	uint16_t timeout;

	// Enable HSI clock and switch to it while we mess with the PLLs
	RCC->CR |= RCC_CR_HSION;
	timeout = 0xFFFF;
	while (!(RCC->CR & RCC_CR_HSIRDY) && timeout--);
	RCC->CFGR = (RCC->CFGR & ~(RCC_CFGR_SW)) | RCC_CFGR_SW_HSI;

	//Disable PLL and HSE
	RCC->CR &= ~RCC_CR_PLLON;
	RCC->CR &= ~RCC_CR_HSEON;

	setBypass();
	clockspeed = 8;
	if (source != 0) {
		setPLL();
		clockspeed = 168;
	}

	//Update system core clock speed for peripherals to set configurations properly
	SystemCoreClockUpdate();

	//Reinitialize peripherals because changing the clock source has messed up all the clocking
	init();
	if (!usbSerialEnabled) {
		usart_init();
	}

	clockSource = (RCC->CFGR & RCC_CFGR_SWS) >> 2;

	//Disable SysTick interrupt to avoid spikes every 1ms
	SysTick->CTRL = SysTick_CTRL_CLKSOURCE_Msk | SysTick_CTRL_ENABLE_Msk;
}


//Function to bypass the internal clock system with an external clock source
void setBypass() {
	uint16_t timeout;

	//Enable HSE bypass
	RCC->CR |= RCC_CR_HSEBYP;
	//Enable HSE
	RCC->CR |= RCC_CR_HSEON;

	//Wait for HSE and set it as the clock source
	timeout = 0xFFFF;
	while ((RCC->CR & RCC_CR_HSERDY) && timeout--);
	RCC->CFGR = (RCC->CFGR & ~(RCC_CFGR_SW)) | RCC_CFGR_SW_HSE;
}


//Function to reconfigure the internal PLLs
void setPLL() {
	uint16_t timeout;

	//disable PLL
	RCC->CR &= ~RCC_CR_PLLON;
	//reconfigure settings for 168 MHz
	RCC_PLLConfig(RCC_PLLSource_HSE, 8, 336, 2, 7);
	//re-enable PLL
	RCC->CR |= RCC_CR_PLLON;

	//Wait for PLL and set it as the clock source
	timeout = 0xFFFF;
	while ((RCC->CR & RCC_CR_PLLRDY) && timeout--);
	RCC->CFGR = (RCC->CFGR & ~(RCC_CFGR_SW)) | RCC_CFGR_SW_PLL;
}


//Disable peripheral clocks for RSA implementation
void disable_clocks() {
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOC, DISABLE);
	RCC_APB1PeriphClockCmd(RCC_APB1Periph_USART3, DISABLE);
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOF, DISABLE);
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOH, DISABLE);
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOC, DISABLE);
}

//Enable peripheral clocks for RSA implementation
void enable_clocks() {
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOC, ENABLE);
	RCC_APB1PeriphClockCmd(RCC_APB1Periph_USART3, ENABLE);
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOF, ENABLE);
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOH, ENABLE);
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOC, ENABLE);
}

//TRNG enable and disable
void RNG_Enable(void)
{
	  RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_RNG, ENABLE);
	  /* RNG Peripheral enable */
	  RNG_Cmd(ENABLE);
}

void RNG_Disable(void)
{
	  RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_RNG, DISABLE);
}
