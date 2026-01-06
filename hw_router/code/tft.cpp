#include "hardware/spi.h"
#include "displaylib_16/st7789.hpp"

static ST7789_TFT myTFT;
#ifdef __cplusplus
extern "C" {
#endif


#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>


#define BUFFER_SIZE 32
#define BUFFER_SIZE_MASK 0x1f
#define MTU 1500
#define READ_SIZE 25*34

static uint8_t buffer[BUFFER_SIZE][MTU] = {0};
static uint16_t sizes[BUFFER_SIZE] = {0};

#define TYPE_SYSTEM 2
#define TYPE_REQUEST 1
#define TYPE_REPLY 0
static uint8_t types[BUFFER_SIZE] = {0};

//static uint8_t slot = 0;

static uint16_t total = 0; // TODO. make it 32-bit?

static uint8_t display_line = 1; // 25 lines, so 1 - 25

volatile uint64_t last_render = 0;

#define TOP_FIXED 21
#define BOTTOM_FIXED 21

static uint8_t display[25][34] = {0};

static uint32_t LAST_PUSH_SEQ = 0;

static uint8_t TAIL = 0; // tail is set on write
static uint8_t HEAD = 0; // head is set after display



void write_next(const uint8_t* data, uint32_t size, uint8_t type) {
    uint16_t idx = TAIL; //slot++ & BUFFER_SIZE_MASK;

    if (total != BUFFER_SIZE) {
        total++;
    }

    sizes[idx] = size;
    types[idx] = type;

    memcpy(buffer[idx], data, size);

    TAIL = (idx + 1) & BUFFER_SIZE_MASK;
}

void write_tcp_data(const uint32_t* data, int32_t bytes_to_skip, uint32_t size, uint32_t data_size, uint32_t seq, uint8_t type) {
/*
    printf("dump of eth packet::");
    for (uint32_t i = 0 ; i < size ; i++) {
    	printf("%08x ", data[i]);    		
    }
    printf("\n");
*/     
    if (LAST_PUSH_SEQ != seq) {
    	LAST_PUSH_SEQ = seq;
    } else {
    	return;
    }

    uint16_t idx = TAIL;//slot++ & BUFFER_SIZE_MASK;    

    //printf("write_tcp_data::idx=%u seq=|%u| dsize=|%u| size=|%u|\n", (idx), seq, data_size, size);

    if (total != BUFFER_SIZE) {
        total++;
    }

    sizes[idx] = data_size;
    types[idx] = type;
    
    uint8_t* buf = buffer[idx];
    
    //int32_t bytes_to_skip = data_size % 4; // HAS TO BE INT
    int32_t pos = 0;

    if (bytes_to_skip-- > 0) {
        uint32_t b = data[size - 1 - (data_size / 4)];      	                
        if (bytes_to_skip-- <= 0) {
            buf[pos++] = ((b >> 16) & 0xFF);
            //printf("%02x ", ((b >> 16) & 0xFF));
        }
        if (bytes_to_skip-- <= 0) {
            buf[pos++] = ((b >>  8) & 0xFF);
            //printf("%02x ", ((b >> 8) & 0xFF));
        }
        if (bytes_to_skip-- <= 0) {
            buf[pos++] = ((b >>  0) & 0xFF);
            //printf("%02x ", ((b >> 0) & 0xFF));
        }        	                
    }
    
    for (uint32_t i = size - (data_size / 4); i < size; i++) {
        uint32_t b = data[i];
        buf[pos++] = ((b >> 24) & 0xFF);
        buf[pos++] = ((b >> 16) & 0xFF);
        buf[pos++] = ((b >>  8) & 0xFF);
        buf[pos++] = ((b >>  0) & 0xFF);        
        //printf("%02x ", ((b >> 24) & 0xFF));
        //printf("%02x ", ((b >> 16) & 0xFF));
        //printf("%02x ", ((b >>  8) & 0xFF));
        //printf("%02x ", ((b >>  0) & 0xFF));
    }
    
    TAIL = (TAIL + 1) & BUFFER_SIZE_MASK;
/*    
    printf("write_tcp_data::end\n");
    printf("write_tcp_data::written::");
    for (size_t i = 0; i < data_size; i++) {
        printf("%c", buf[i]);        
    }
    printf("|\n");
*/    
    //printf("\n");
}


//                C_BLACK   = 0x0000, /**< Black */
//                C_BLUE    = 0x001F, /**< Blue */
//                C_RED     = 0xF800, /**< Red */
//                C_GREEN   = 0x07E0, /**< Green */
//                C_CYAN    = 0x07FF, /**< Cyan */
//                C_MAGENTA = 0xF81F, /**< Magenta */
//                C_YELLOW  = 0xFFE0, /**< Yellow */
//                C_WHITE   = 0xFFFF, /**< White */
//                C_TAN     = 0xED01, /**< Tan */
//                C_GREY    = 0x9CD1, /**< Grey */
//                C_BROWN   = 0x6201, /**< Brown */
//                C_DGREEN  = 0x01C0, /**< Dark Green */
//                C_ORANGE  = 0xFC00, /**< Orange */
//                C_NAVY    = 0x000F, /**< Navy */
//                C_DCYAN   = 0x03EF, /**< Dark Cyan */
//                C_MAROON  = 0x7800, /**< Maroon */
//                C_PURPLE  = 0x780F, /**< Purple */
//                C_OLIVE   = 0x7BE0, /**< Olive */
//                C_LGREY   = 0xC618, /**< Light Grey */
//                C_DGREY   = 0x7BEF, /**< Dark Grey */
//                C_GYELLOW = 0xAFE5, /**< Greenish Yellow */
//                C_PINK    = 0xFC18, /**< Pink */
//                C_LBLUE   = 0x7E5F, /**< Light Blue */
//                C_BEIGE   = 0xB5D2  /**< Beige */


//write (const uint8_t *buffer, size_t size)
void print(const uint8_t* data, size_t size, uint8_t type) {
/*
    printf("render_display::");
    for (size_t i = 0; i < size; i++) {
        printf("%c", data[i]);        
    }
    printf("\n");
    return;
*/

    if (type == TYPE_SYSTEM) {
    	myTFT.setTextColor(myTFT.C_WHITE, myTFT.C_BLACK);
        myTFT.Print::write(data, size);        
    } else if (type == TYPE_REQUEST) {
        myTFT.setTextColor(myTFT.C_BLUE, myTFT.C_BLACK);
        myTFT.Print::write(data, size);
        myTFT.setTextColor(myTFT.C_WHITE, myTFT.C_BLACK);
    } else {
        myTFT.setTextColor(myTFT.C_GYELLOW, myTFT.C_BLACK);
        myTFT.Print::write(data, size);
        myTFT.setTextColor(myTFT.C_WHITE, myTFT.C_BLACK);
    }
    
    if (data[size-1] != '\n') {
    	myTFT.print('\n');
    }
}


void render_display() {
	/*
    uint8_t idx = 0;
    if (slot > 0) {
    	idx = (slot - 1) & 0x3F;
    }
    */

/*    
    if (time_us_32() - last_render > 500000) {
        last_render = time_us_32();
    } else {
    	printf("display returning cuz timer");
    	return;
    }
*/
    if (time_us_64() - last_render > 1000000ULL) {
        last_render = time_us_64();
        //printf("render_display timer ticks\n");
    } else {	    
        return;
    }
    
    // since last draw, has there been a gap which we have yet to render
    bool no_gap = (TAIL - HEAD == 1);
    
    if (TAIL == HEAD) {
    	return;
    } else {
    	//printf("HEAD(%u) != TAIL(%u) thus setting HEAD to %u", HEAD, TAIL, (TAIL - 1) & BUFFER_SIZE_MASK);
    	
    	// just put idx on last
    	HEAD = (TAIL - 1) & BUFFER_SIZE_MASK;
    	//HEAD = TAIL & BUFFER_SIZE_MASK;
    }
    
    uint8_t idx = HEAD;// & BUFFER_SIZE_MASK;
    //HEAD = (HEAD + 1) & 0x3F;
    
    //printf("render_display::idx=%u\n", idx);
    
    
    uint16_t size = sizes[idx];
    int16_t padded_size = sizes[idx];
    if (size % 34) {
        padded_size += 34 - (size % 34);
    }
    uint8_t* data = buffer[idx];
    uint8_t type = types[idx];
    
    if (total == 1) {
        // first time displaying, so only check
        // packet's size to determine size to write
        // and then write from top of active window
        
        //memcpy(display[display_line-1], data, size); // akin to print fn
        myTFT.setCursor(0,21);
        print(data, size, type);
        display_line += (padded_size / 34);
        
        HEAD = (HEAD + 1) & BUFFER_SIZE_MASK;
        //printf("render_display::yielding\n");
        return;        
    }

    if (no_gap && display_line + (padded_size / 34) <= 26) {
        //memcpy(display[display_line-1], data, size); // akin to print fn
        print(data, size, type);
        display_line += padded_size / 34;
    } else {

        // display full, we have to scroll up to make space
        int16_t lines_to_scroll_up = padded_size / 34;
        if (lines_to_scroll_up >= 25) {

            // this item takes whole screen
            myTFT.fillScreen(myTFT.C_BLACK);
            //memcpy(display[0], data, 34 * 25); // akin to print fn
            //print(data, size, type);
            print(data, 34 * 25, type);
        } else {

  
            // TODO bound it
            myTFT.fillScreen(myTFT.C_BLACK);
            uint8_t final_idx = idx;
            
            uint16_t items = total;
            int32_t budget = READ_SIZE;
            uint8_t idx = final_idx; //(final_idx - 1) & BUFFER_SIZE_MASK; //(slot - 1);
            while (items != 0 && budget > 0) {
                //printf("reading back idx = %d\n", idx);
                uint8_t* data = buffer[idx];
                uint32_t size = sizes[idx];
                int16_t padded_size = sizes[idx];
                if (size % 34) {
                    padded_size += 34 - (size % 34);
                }

                
                if (budget < padded_size) {
                    // either skip entirely
                    break;
                    
                    // or just print what's left
                    //for (uint32_t i = 0 ; i < budget ; i++) {
                    //    printf("%c", data[i]);
                    //}
                    //break;                        
                }
                        
                //for (uint32_t i = 0 ; i < size ; i++) {
                //    printf("%c", data[i]);
                //}
                
                budget -= padded_size;
                idx = (idx - 1) & BUFFER_SIZE_MASK;
                items--;
            }
            
            // idx = starting idx of oldest
            // print until consumes whole budget
            
            budget = READ_SIZE;
            items = total;
            myTFT.setCursor(0,21);
            display_line = 1;
            myTFT.setTextCharPixelOrBuffer(false);
            while (items != 0 && budget > 0) {                    
                uint32_t size = sizes[idx];
                int16_t padded_size = sizes[idx];
                if (size % 34) {
                    padded_size += 34 - (size % 34);
                }
                uint8_t* data = buffer[idx];
                uint8_t type = types[idx];
                //printf("printing data=|%s| type=|%u|\n", data, type);
                print(data, size, type);
                //MILLISEC_DELAY(1000);
                display_line += (padded_size / 34);
                
                idx = (idx + 1) & BUFFER_SIZE_MASK;
                
                if (idx == final_idx) {
                    myTFT.setTextCharPixelOrBuffer(true);
                }
                
                items--;
                budget -= padded_size;
            }
        }
    }

    HEAD = (HEAD + 1) & BUFFER_SIZE_MASK;
    //printf("render_display::yielding\n");
}

#ifdef __cplusplus
}
#endif

void tft_init()
{
    //stdio_init_all(); // optional for error messages , Initialize chosen serial port, default 38400 baud
	//MILLISEC_DELAY(TEST_DELAY1);
	//printf("TFT: Start\r\n");
	
//*************** USER OPTION 0 SPI_SPEED + TYPE ***********
	bool bhardwareSPI = true; // true for hardware spi, false for software
	
	if (bhardwareSPI == true) { // hw spi
		//uint32_t TFT_SCLK_FREQ =  8000 ; // Spi freq in KiloHertz , 1000 = 1Mhz
		uint32_t TFT_SCLK_FREQ =  40000 ;
		myTFT.TFTInitSPIType(TFT_SCLK_FREQ, spi0); 
	} else { // sw spi
		uint16_t SWSPICommDelay = 0; // optional SW SPI GPIO delay in uS
		myTFT.TFTInitSPIType(SWSPICommDelay);
	}
//*********************************************************
// ******** USER OPTION 1 GPIO *********
// NOTE if using Hardware SPI clock and data pins will be tied to 
// the chosen interface eg Spi0 CLK=18 DIN=19)
	int8_t SDIN_TFT = 19;
	int8_t SCLK_TFT = 18;
	int8_t DC_TFT = 22;
	int8_t CS_TFT = 20;
	int8_t RST_TFT = 21;
	myTFT.setupGPIO(RST_TFT, DC_TFT, CS_TFT, SCLK_TFT, SDIN_TFT);
//**********************************************************

// ****** USER OPTION 2 Screen Setup ****** 
	uint16_t OFFSET_COL = 0;  // These offsets can be adjusted for any issues->
	uint16_t OFFSET_ROW = 0;  // with screen manufacture tolerance/defects
	uint16_t TFT_WIDTH = 240; // Screen width in pixels
	uint16_t TFT_HEIGHT = 280; // Screen height in pixels
	myTFT.TFTInitScreenSize(OFFSET_COL, OFFSET_ROW , TFT_WIDTH , TFT_HEIGHT);
// ******************************************

	myTFT.TFTST7789Initialize();

    // my code here

	myTFT.fillScreen(myTFT.C_BLACK);
	myTFT.setRotation(myTFT.Degrees_270);

	char logo[] = " Hermetic Wallet";
	char title[] = "    Welcome to the other side";

	myTFT.setFont(font_orla);
	myTFT.writeCharString(5, 100, logo);
	
	myTFT.setFont(font_retro);
	myTFT.writeCharString(5, 130, title);
	
	MILLISEC_DELAY(1000);
	
	myTFT.fillScreen(myTFT.C_BLACK);
	myTFT.setTextWrap(true);
	myTFT.setFont(font_sinclairS);
	

}

void tft_hello_world() {
	
	for (uint32_t i = 0; i < 1; i++) {
	    char buf[] = "(x) The quick brown fox jumps over the lazy dog\n";
	    buf[1] = '0' + i;
	    write_next((uint8_t*)&buf, 48, TYPE_SYSTEM);
	    render_display();
	}

	myTFT.setTextCharPixelOrBuffer(true);
}

/*

void tft_hello_world_old() {
	myTFT.fillScreen(myTFT.C_BLACK);
	myTFT.setRotation(myTFT.Degrees_270);
	
	/*
	char logo[] = " Hermetic Wallet";
	char title[] = "    Welcome to the other side";

	myTFT.setFont(font_orla);
	myTFT.writeCharString(5, 100, logo);
	
	myTFT.setFont(font_retro);
	myTFT.writeCharString(5, 130, title);
	
	MILLISEC_DELAY(1000);
	myTFT.fillScreen(myTFT.C_BLACK);
	*//*
	
	char buf1[] = "The quick brown fox jumps over"; // 30 chars
	char buf2[] ="the lazy dog(1) The quick brown"; // 31 chars
	char buf3[] = "fox jumps over the lazy dog(2) The quick brown fox jumps over the lazy dog(3) The quick brown fox jumps over the lazy dog(4) The quick brown fox jumps over the lazy dog(5) The quick brown fox jumps over the lazy dog(6) The quick brown fox jumps over the lazy dog(7) The quick brown fox jumps over the lazy dog(8) The quick brown fox jumps over the lazy dog(9) The quick brown fox jumps over the lazy dog(10) The quick brown fox jumps over the lazy dog(11) The quick brown fox jumps over the lazy dog(12) The quick brown fox jumps over the lazy dog(13) The quick brown fox jumps over the lazy dog(14) The quick brown fox jumps over the lazy dog(15) The quick brown fox jumps over the lazy dog(16) The quick brown fox jumps over the lazy dog(17) The quick brown fox jumps over the lazy dog(18) The quick brown fox jumps over the lazy dog(19) The quick brown fox jumps over th"; // 873 chars

	myTFT.setTextWrap(true);
	myTFT.setFont(font_sinclairS);
	myTFT.writeCharString(22, 5, buf1);
	myTFT.writeCharString(10, 13, buf2);
	myTFT.setTextCharPixelOrBuffer(true);
	//myTFT.writeCharString(5, 25, buf3);
	//myTFT.writeCharString(5, 85, buf4);
	//myTFT.setAddrWindow(20, 30, 260, 250);
	myTFT.setCursor(5,21);
	myTFT.print(buf3);
	
	// UI items
	myTFT.setTextColor(myTFT.C_ORANGE, myTFT.C_WHITE);
	char setting[] = "setting";
	myTFT.writeCharString(22, 225, setting);
	
	char counter[] = "001/512";
	myTFT.writeCharString(280 - 7*12, 225, counter);
	myTFT.setTextColor(myTFT.C_WHITE, myTFT.C_BLACK);
	
	//tft_display_buf((uint8_t *)&"ping back", 8);
	
	//MILLISEC_DELAY(60000);
	//myTFT.fillScreen(myTFT.C_BLACK);
}

*/

