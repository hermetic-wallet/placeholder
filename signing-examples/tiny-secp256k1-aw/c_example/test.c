#include <stdio.h>
#include <stdint.h>

typedef uint8_t uECC_word_t;
typedef uint16_t uECC_dword_t;
typedef int8_t wordcount_t;

#define uECC_WORD_BITS 8

static void muladd(uECC_word_t a,
                     uECC_word_t b,
                     uECC_word_t *r0,
                     uECC_word_t *r1,
                     uECC_word_t *r2) {
      uECC_dword_t p = (uECC_dword_t)a * b;
	  printf("  muladd:: p=0x%04x", p);
      uECC_dword_t r01 = ((uECC_dword_t)(*r1) << uECC_WORD_BITS) | *r0;
	  printf(" r0 = 0x%02x r1 = 0x%02x  r01 = 0x%04x", *r0, *r1, r01);
      r01 += p;
	  printf(" new_r01 = 0x%04x", r01);
	  printf("\n");
      *r2 += (r01 < p);
      *r1 = r01 >> uECC_WORD_BITS;
      *r0 = (uECC_word_t)r01;
 }

void mult(uECC_word_t *result,
                                  const uECC_word_t *left,
                                  const uECC_word_t *right,
                                  wordcount_t num_words) {
      uECC_word_t r0 = 0;
      uECC_word_t r1 = 0;
      uECC_word_t r2 = 0;
      wordcount_t i, k;

      /* Compute each digit of result in sequence, maintaining the carries. */
      for (k = 0; k < num_words; ++k) {
          for (i = 0; i <= k; ++i) {
              muladd(left[i], right[k - i], &r0, &r1, &r2);
			  printf("[k = %2d, i = %2d]\t\t left_%02d * right_%02d (0x%02x * 0x%02x)\t[r0 = 0x%02x, r1 = 0x%02x, r2 = 0x%02x]\n", k, i,i, k-i, left[i], right[k-i], r0,r1,r2);
          }
          result[k] = r0;
          r0 = r1;
          r1 = r2;
          r2 = 0;
      }
      for (k = num_words; k < num_words * 2 - 1; ++k) {
          for (i = (k + 1) - num_words; i < num_words; ++i) {
              muladd(left[i], right[k - i], &r0, &r1, &r2);
          }
          result[k] = r0;
          r0 = r1;
          r1 = r2;
          r2 = 0;
      }
      result[num_words * 2 - 1] = r0;
  }

int main() {
	/*
	uECC_word_t three[32] = {
		3,0,0,0,0,0,0,0, 
		0,0,0,0,0,0,0,0, 
		0,0,0,0,0,0,0,0, 
		0,0,0,0,0,0,0,0, 
	};
	uECC_word_t num[32] = {
		32,31,30,29,28,27,26,25, 
		24,23,22,21,20,19,18,17, 
		16,15,14,13,12,11,10,9, 
		8,7,6,5,4,3,2,1, 
	};
	*/
	uECC_word_t three[32] = {
		3,0,0,0,0,0,0,0, 
		0,0,0,0,0,0,0,0, 
		0,0,0,0,0,0,0,0, 
		0,0,0,0,0,0,0,0, 
	};
	uECC_word_t num[32] = {
		255,0,0,0,0,0,0,0, 
		0,0,0,0,0,0,0,0, 
		0,0,0,0,0,0,0,0, 
		0,0,0,0,0,0,0,0, 
	};

	uECC_word_t Gx[32] = { 
		0x98, 0x17, 0xf8, 0x16, 
		0x5b, 0x81, 0xf2, 0x59, 
		0xd9, 0x28, 0xce, 0x2d, 
		0xdb, 0xfc, 0x9b, 0x02, 
		0x07, 0x0b, 0x87, 0xce, 
		0x95, 0x62, 0xa0, 0x55, 
		0xac, 0xbb, 0xdc, 0xf9, 
		0x7e, 0x66, 0xbe, 0x79
	};
	uECC_word_t product[32 * 2];

	//mult(num_x_three, num, three, 32);
	//mult(product, left, right, 32);
	mult(product, Gx, Gx, 32);
	//mult(product, three, Gx, 32);
	//mult(product, Gx, three, 32);

	printf("hello world\nproduct = 0x");

	for (int i = 0 ; i < 64 ; ++i)
		printf("%02x", product[i]);
	printf("\n");

	printf("product = 0x");
	for (int i = 64 ; i >= 0 ; --i)
		printf("%02x", product[i]);
	printf("\n");
}
