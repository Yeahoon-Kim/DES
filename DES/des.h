#ifndef __DES_H__
#define __DES_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef uint64_t DES_STATE_t;


//구현함수
void DES_enc(DES_STATE_t * C, DES_STATE_t P, DES_STATE_t K);
void DES_dec(DES_STATE_t * P, DES_STATE_t C, DES_STATE_t K);


///////////TEST Vectors
typedef struct {
	DES_STATE_t P;
	DES_STATE_t C;
	DES_STATE_t K;
}DES_TV_t;



static DES_TV_t des_tvs[] = {
	{
		0x0123456789abcdefULL, //P
		0xb98630a30bd8f6d7ULL, //C
		0x0011223344556677ULL, //K
	},//0
	{
		0x0000000000000000ULL, //P
		0x8CA64DE9C1B123A7ULL, //C
		0x0000000000000000ULL, //K
	},//1
	{
		0xFFFFFFFFFFFFFFFFULL, //P
		0x7359b2163e4edc58ULL, //C
		0xFFFFFFFFFFFFFFFFULL, //K
	},//2
	{
		0x0123456789ABCDEFULL, //P
		0xed39d950fa74bcc4ULL, //C
		0xFEDCBA9876543210ULL, //K
	},//3

	{
		0xABCDEFABCDEFABCDULL, //P
		0xf488c75a67b05ae4ULL, //C
		0xABCDEFABCDEFABCDULL, //K
	},//4
	{
		0x1111111111111111ULL, //P
		0xf40379ab9e0ec533ULL, //C
		0x1111111111111111ULL, //K
	},//5
	{
		0x2222222222222222ULL, //P
		0x0f8adffb11dc2784ULL, //C
		0x2222222222222222ULL, //K
	},//6

	{
		0x3333333333333333ULL, //P
		0x0432ed386f2de328ULL, //C
		0x3333333333333333ULL, //K
	},//7
};

#define NUM_DES_TVS (sizeof(des_tvs)/sizeof(DES_TV_t))

#ifdef __cplusplus
}
#endif /*extern "C"*/
#endif /*__DES_H__*/