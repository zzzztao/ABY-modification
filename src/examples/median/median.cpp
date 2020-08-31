/**
 \file 		abyfloat.cpp
 \author	daniel.demmler@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
 Copyright (C) 2019 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
            it under the terms of the GNU Lesser General Public License as published
            by the Free Software Foundation, either version 3 of the License, or
            (at your option) any later version.
            ABY is distributed in the hope that it will be useful,
            but WITHOUT ANY WARRANTY; without even the implied warranty of
            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
            GNU Lesser General Public License for more details.
            You should have received a copy of the GNU Lesser General Public License
            along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
#include "../../abycore/aby/abyparty.h"
#include "../../abycore/circuit/share.h"
#include "../../abycore/circuit/booleancircuits.h"
#include "../../abycore/sharing/sharing.h"
#include <cassert>
#include <iomanip>
#include <iostream>
#include <math.h>
#include <time.h>

//#define RAND_MAX = 4294967296;
//#define N = 25;

void read_test_options(int32_t* argcp, char*** argvp, e_role* role,
	uint32_t* bitlen, uint32_t* nvals, uint32_t* secparam, std::string* address,
	uint16_t* port, int32_t* test_op, uint32_t* test_bit) {

	uint32_t int_role = 0, int_port = 0, int_testbit = 0;

	parsing_ctx options[] =
	{ {(void*) &int_role, T_NUM, "r", "Role: 0/1", true, false },
	{(void*) &int_testbit, T_NUM, "i", "test bit", false, false },
	{(void*) nvals, T_NUM, "n",	"Number of parallel operation elements", false, false },
	{(void*) bitlen, T_NUM, "b", "Bit-length, default 32", false,false },
	{(void*) secparam, T_NUM, "s", "Symmetric Security Bits, default: 128", false, false },
	{(void*) address, T_STR, "a", "IP-address, default: localhost", false, false },
	{(void*) &int_port, T_NUM, "p", "Port, default: 7766", false, false },
	{(void*) test_op, T_NUM, "t", "Single test (leave out for all operations), default: off", false, false },

	};

	if (!parse_options(argcp, argvp, options,
		sizeof(options) / sizeof(parsing_ctx))) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
	std::cout << "Exiting" << std::endl;
	exit(0);
	}

	assert(int_role < 2);
	*role = (e_role) int_role;

	if (int_port != 0) {
		assert(int_port < 1 << (sizeof(uint16_t) * 8));
		*port = (uint16_t) int_port;
	}

	*test_bit = int_testbit;
}

void init_number(e_role role, uint32_t nvals, uint64_t a_number[25], uint64_t b_number[25]){

	if (role = SERVER){
		srand((int)time(0));
		for( int i = 0; i < 25; i++){
			a_number[i] = rand()%4294967296;
			std::cout  << a_number[i] << std::endl;
		}
	}

	if (role = CLIENT){
		srand((int)time(0));
		for( int i = 0; i < 25; i++){
			b_number[i] = rand()%4294967296;
			std::cout  << b_number[i] << std::endl;
		}
	}

}


void split_number(e_role role, uint32_t nvals, uint64_t a_number[25], uint64_t b_number[25], uint32_t a_split1[25], uint32_t a_split2[25], uint32_t b_split1[25], uint32_t b_split2[25]){

	if (role = SERVER){
		//srand((int)time(0));
		for( int i = 0; i < 25; i++){
			a_split1[i] = rand()%4294967296;
			a_split2[i] = (a_number[i] + 4294967296 - a_split1[i])%4294967296;
			std::cout << a_split1[i] << ";" << a_split2[i]<< std::endl;
		}
	}

	if (role = CLIENT){
		srand((int)time(0));
		for( int i = 0; i < 25; i++){
			b_split1[i] = rand()%4294967296;
			b_split2[i] = (b_number[i] + 4294967296 - b_split1[i])%4294967296;
			std::cout << b_split1[i] << ";" << b_split2[i]<< std::endl;
		}
	}
}

void test_median(e_role role, const std::string& address, uint16_t port, seclvl seclvl, uint32_t nvals, uint32_t nthreads,
	e_mt_gen_alg mt_alg, e_sharing sharing) {
//, uint32_t a_split1[25], uint32_t a_split2[25], uint32_t b_split1[25], uint32_t b_split2[25]
	uint32_t bitlen = 32;

	std::string circuit_dir = "../../bin/circ/";

	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg, 100000, circuit_dir);

	std::vector<Sharing*>& sharings = party->GetSharings();

	BooleanCircuit* circ = (BooleanCircuit*) sharings[sharing]->GetCircuitBuildRoutine();

/*for(int l = 0; l < 10; l++)
	{
		
	uint32_t avals[nvals];
	uint32_t bvals[nvals];
	uint32_t asum[nvals];
	uint32_t bsum[nvals];

	srand((int)time(0));
	int i = 0;
	for (i = 0; i < nvals; i++)
	{
		avals[i] = rand()%100000000; 
		bvals[i] = rand()%100000000;
		//std::cout << "llll:" << avals[i] << bvals[i]  << std::endl;
	}


    int ab[nvals];
	for(i = 0; i < nvals; i++)
		ab[i] = avals[i]+bvals[i];

	std::sort(ab, ab + nvals);

	std::cout << "Circuit Result:" << ab[24] + ab[25] << std::endl;*/
	


	uint32_t number = 25;
	uint32_t  a_split1[number], b_split1[number], a_split2[number], b_split2[number];
	uint32_t  a_number[number], b_number[number];
	uint32_t  a_mask[number], b_mask[number];
	uint32_t  a_mask_split1[number], a_mask_split2[number], b_mask_split1[number], b_mask_split2[number];
	/*if (role = SERVER){
		srand((int)time(0));
		for( int i = 0; i < 25; i++){
			a_number[i] = rand()%4294967296;
			a_split1[i] = rand()%4294967296;
			a_split2[i] = (a_number[i] + 4294967296 - a_split1[i])%4294967296;
			std::cout << a_number[i] << ";" << a_split1[i] << ";" << a_split2[i]<< std::endl;
		}
	}

	if (role = CLIENT){
		srand((int)time(0));
		for( int i = 0; i < 25; i++){
			b_number[i] = rand()%4294967296;
			b_split1[i] = rand()%4294967296;
			b_split2[i] = (b_number[i] + 4294967296 - b_split1[i])%4294967296;
			std::cout << b_number[i] << ";" << b_split1[i] << ";" << b_split2[i]<< std::endl;
		}
	}*/	
	int j = 0, i ;
	for(int k= 0; k<5;k++){
	srand((int)time(0));
	//4294967296
	int l=50;
	for( int i = 0; i < 25; i++){

			b_number[i] = 50-i;
			//rand() % 4294967296;
			b_split1[i] = rand() % 4294967296;
			b_split2[i] = (b_number[i] + 4294967296 - b_split1[i])%4294967296;
			//std::cout << b_number[i] << ";" << b_split1[i] << ";" << b_split2[i]<< std::endl;
			a_number[i] = 25-i;
			//rand() % 4294967296;
			a_split1[i] = rand() % 4294967296;
			a_split2[i] = (a_number[i] + 4294967296 - a_split1[i])%4294967296;
			//std::cout << a_number[i] << ";" << a_split1[i] << ";" << a_split2[i]<< std::endl;

			a_mask[i] = rand() % 4294967296;
			a_mask_split1[i] = rand() % 4294967296;
			a_mask_split2[i] = (a_mask[i] + 4294967296 - a_mask_split1[i])%4294967296;

			b_mask[i] = rand() % 4294967296;
			b_mask_split1[i] = rand() % 4294967296;
			b_mask_split2[i] = (b_mask[i] + 4294967296 - b_mask_split1[i])%4294967296;
			
		}

	

	uint32_t ab[50];
	for(i = 0; i < 25; i++)
	{
		ab[i] = a_number[i];
		ab[i+25] = b_number[i];
	}
		

	std::sort(ab, ab + 50);

	std::cout << "ver Result:" << ab[24] + ab[25] << std::endl;

	
	uint32_t asum[nvals];
	uint32_t bsum[nvals];

	for( i = 0; i < nvals; i++)
	{
		asum[i] = 0;
		//bsum[i] = 0;
	}

	clock_t start2, finish2;
    double  duration2;
	start2 = clock();

	uint32_t output, abcmp_mask[50];
	

	share* ain1[25], * bin1[25],* ain2[25], * bin2[25],* asin[nvals],/* bsin[nvals],*/* abin[nvals];
	share* as_mask_split1[25],* as_mask_split2[25],* bs_mask_split1[25],* bs_mask_split2[25];
	share* abs_mask[50],* abscmp_mask[50];


   
	for (size_t i = 0; i < 25; i++){

		ain1[i] = circ->PutINGate(a_split1[i], bitlen, SERVER);
		bin1[i] = circ->PutINGate(b_split1[i], bitlen, SERVER);

		ain2[i] = circ->PutINGate(a_split2[i], bitlen, CLIENT);
		bin2[i] = circ->PutINGate(b_split2[i], bitlen, CLIENT);

		as_mask_split1[i] = circ->PutINGate(a_mask_split1[i], bitlen, SERVER);
		bs_mask_split1[i] = circ->PutINGate(b_mask_split1[i], bitlen, SERVER);

		as_mask_split2[i] = circ->PutINGate(a_mask_split2[i], bitlen, CLIENT);
		bs_mask_split2[i] = circ->PutINGate(b_mask_split2[i], bitlen, CLIENT);

	}

	for (size_t i = 0; i < nvals; i++){

		asin[i] = circ->PutINGate(asum[i], bitlen, SERVER);
		//bsin[i] = circ->PutINGate(bsum[i], bitlen, CLIENT);

	}
	

	for (size_t i = 0; i < 25; i++)
	{
		abin[i] = circ->PutADDGate(ain1[i], ain2[i]);
		abin[i+25] = circ->PutADDGate(bin1[i], bin2[i]);
	}

	for (size_t i = 0; i < 25; i++)
	{
		abs_mask[i] = circ->PutADDGate(as_mask_split1[i], as_mask_split2[i]);
		abs_mask[i+25] = circ->PutADDGate(bs_mask_split1[i], bs_mask_split2[i]);
	}		
	
	uint32_t a = 23, b = 25, c = 0;

	share* m1= circ->PutINGate(a, bitlen, CLIENT);
	share* m2 = circ->PutINGate(b, bitlen, CLIENT);
	share* zreo =  circ->PutINGate(c, bitlen, CLIENT);


	for(j = 0; j < nvals; j++)
	{
		for (i = 0; i < nvals; i++)
		{
			asin[j] = circ->PutADDGate(circ->PutGTGate(abin[j], abin[i]), asin[j]);

			//bsin[j] = circ->PutADDGate(circ->PutGTGate(abin[j], abin[i]), bsin[j]);
		}
	}


	share* median1 = zreo;
	share* median2 = zreo;


	for (i = 0; i < nvals; i++){	

		median2 = circ->PutADDGate(circ->PutMULGate(circ->PutGTGate(asin[i], m2), abin[i]), median2);

		median1 = circ->PutADDGate(circ->PutMULGate(circ->PutGTGate(asin[i], m1), abin[i]), median1);
	}

	share* median = circ->PutSUBGate(median1, median2);

	for(i = 0; i < nvals; i++){

		abscmp_mask[i] = circ->PutADDGate(asin[i], abs_mask[i]);
	}	

	//share* median_out = circ->PutOUTGate(median1, ALL);

	//share* ceshi_out = circ->PutOUTGate(median2, ALL);

	

	share* median_out = circ->PutOUTGate(median, ALL);

	share* abcmp_mask_out[50];

	for(i = 0; i < nvals; i++){

		abcmp_mask_out[i] = circ->PutOUTGate(abscmp_mask[i], ALL);
		
	}

	party->ExecCircuit();

	output = median_out->get_clear_value<uint32_t>();
	//output1 = ceshi_out->get_clear_value<uint32_t>();
	//output2 = zero_out->get_clear_value<uint32_t>();

	std::cout << "Circuit Result:" << output << std::endl;
	if(output == (ab[24] + ab[25]))
		std::cout << "yes ok!!!" <<std::endl;
	else
		std::cout << "淦" <<std::endl;
	//std::cout << "Circuit Result:" << output1 << std::endl;;
	//std::cout << "Circuit Result:" << output2 << std::endl;;
	for(i = 0; i < nvals; i++){

		abcmp_mask[i] =  abcmp_mask_out[i]->get_clear_value<uint32_t>();

	}


	uint32_t temp[50], temp_cmp[50];
	for(i = 0; i < 25; i++ ){
		temp[i] = a_mask_split1[i] + a_mask_split2[i];
		temp[i+25] = b_mask_split1[i] + b_mask_split2[i];
	}
	for(i = 0; i < 50; i++ ){
		temp_cmp[i] = abcmp_mask[i] - temp[i];
	}

	//std::sort(temp_cmp, temp_cmp+50);

	for(i = 0; i < 50; i++){

		std::cout << "cmp:" <<temp_cmp[i] << std::endl;
		std::cout << "cmp:" <<abcmp_mask[i] << std::endl;
	}
	//for(i = 0; i < 25; i++){

	//	std::cout << "acmp:" << abcmp_mask[i] - a_mask[i] << std::endl;
	//	std::cout << "bcmp:" << abcmp_mask[i+25] - b_mask[i] << std::endl;
//	}
	finish2 = clock();
	duration2 = (double)(finish2 - start2) / CLOCKS_PER_SEC;
   	printf( "%f seconds\n", duration2 );
     
	party->Reset();

	}
	delete party;

}


int main(int argc, char** argv) {

	clock_t start, finish;
    double  duration;
    start = clock();
	e_role role;
	uint32_t bitlen = 1, nvals = 50, secparam = 128, nthreads = 1 ,number = 25;

	uint16_t port = 7766;
	std::string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;
	uint32_t test_bit = 0;

	//uint32_t  a_split1[number], b_split1[number], a_split2[number], b_split2[number];
	//uint64_t  a_number[number], b_number[number];

	read_test_options(&argc, &argv, &role, &bitlen, &nvals, &secparam, &address, &port, &test_op, &test_bit);

	seclvl seclvl = get_sec_lvl(secparam);

	//init_number(role, nvals, &a_number[number], &b_number[number]);

	//split_number(role, nvals, &a_number[number], &b_number[number], &a_split1[nvals], &a_split2[nvals], &b_split1[nvals], &b_split1[nvals]);

	/*if (role = SERVER){

		for( int i = 0; i < 25; i++){
			std::cout  << a_number[i] << ";" << a_split1[i] << ";" << a_split2[i]<< std::endl;
		}
		
	}

	if (role = CLIENT){

		for( int i = 0; i < 25; i++){
			std::cout  << b_number[i] << ";" << b_split1[i] << ";" << b_split2[i]<< std::endl;
		}
		
	}*/
//&a_split1[nvals], &a_split2[nvals], &b_split1[nvals], &b_split1[nvals]
	test_median(role, address, port, seclvl, nvals, nthreads, mt_alg, S_BOOL);

    finish = clock();
	duration = (double)(finish - start) / CLOCKS_PER_SEC;
    printf( "%f seconds\n", duration );
	return 0;
}
