#include <stdint.h>

#include "des.h"
#include "check_speed.h"


extern char SUBMISSION_INFO[256];

int main(void)
{
	int i, j;
	DES_STATE_t T, P, C, K;
	double throughput = 0.;

	printf("Submission Info : %s\n", SUBMISSION_INFO);

	//Step 1 : Check Test Vectors
	printf("Step 1 : Check Test Vectors\n");
	for (i = 0; i < NUM_DES_TVS; i++)
	{
		printf("  > %d tv : ", i);
		DES_enc(&T, des_tvs[i].P, des_tvs[i].K);
		if (T != des_tvs[i].C)
		{
			printf("An Error Occurs while Checking the Encryption Function\n");
			goto err;
		}
		DES_dec(&T, des_tvs[i].C, des_tvs[i].K);
		if (T != des_tvs[i].P)
		{
			printf("An Error Occurs while Checking the Decrpytion Function\n");
			goto err;
		}
		printf("Pass\n");
	}
	printf("  >> Good job!! Passed All the Test Vectors\n");


	//Step 2 : Check Performance
	printf("Step 2 : Check Performance\n");
	srand((unsigned int)time(NULL));
	
	
	for (i = 0; i < NUM_CHECK_TIME; i++)
	{
		//Randomly Choosen T
		T = 0;
		T = T << 8; T |= (DES_STATE_t)(rand() & 0xff);
		T = T << 8; T |= (DES_STATE_t)(rand() & 0xff);
		T = T << 8; T |= (DES_STATE_t)(rand() & 0xff);
		T = T << 8; T |= (DES_STATE_t)(rand() & 0xff);

		T = T << 8; T |= (DES_STATE_t)(rand() & 0xff);
		T = T << 8; T |= (DES_STATE_t)(rand() & 0xff);
		T = T << 8; T |= (DES_STATE_t)(rand() & 0xff);
		T = T << 8; T |= (DES_STATE_t)(rand() & 0xff);

		//Randomly Choosen K
		K = 0;
		K = K << 8; K |= (DES_STATE_t)(rand() & 0xff);
		K = K << 8; K |= (DES_STATE_t)(rand() & 0xff);
		K = K << 8; K |= (DES_STATE_t)(rand() & 0xff);
		K = K << 8; K |= (DES_STATE_t)(rand() & 0xff);

		K = K << 8; K |= (DES_STATE_t)(rand() & 0xff);
		K = K << 8; K |= (DES_STATE_t)(rand() & 0xff);
		K = K << 8; K |= (DES_STATE_t)(rand() & 0xff);
		K = K << 8; K |= (DES_STATE_t)(rand() & 0xff);

		CHECK_TIME_START;

		for (j = 0; j < NUM_BLOCKS_OF_DES; j++)
		{
			DES_enc(&C, T, K);
			DES_dec(&P, C, K);
			if (T != P)
			{
				printf("An Error Occurs while Checking the Performance!\n");
				goto err;
			}
			else
			{
				T = C;
			}
		}

		CHECK_TIME_END;
		printf("  > %d its : ", i);
		PRINT_DELTA_TIME(2 * NUM_BLOCKS_OF_DES * 64);
		throughput += OP_TIME;
	}
	printf("  >> On average, %0.4f Mbps\n", ((2 * NUM_BLOCKS_OF_DES * 64)/(throughput/NUM_CHECK_TIME))/(1000*1000));
err:

	return 0;
}