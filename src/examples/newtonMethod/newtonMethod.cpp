/**
 \file 		innerproduct_test.cpp
 \author	sreeram.sadasivam@cased.de
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
 \brief		Inner Product Test class implementation.
 */

//Utility libs
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
#include "../../abycore/sharing/sharing.h"
#include "../../abycore/aby/abyparty.h"
#include "../../abycore/circuit/booleancircuits.h"
#include "../../abycore/circuit/arithmeticcircuits.h"
#include <iostream>
#include <cstdlib>
#include <ctime>

#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/thread.h>


int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role,
		uint32_t* bitlen, uint32_t* numbers, uint32_t* secparam, std::string* address,
		uint16_t* port, int32_t* test_op) {

	uint32_t int_role = 0, int_port = 0;

	parsing_ctx options[] =
			{ { (void*) &int_role, T_NUM, "r", "Role: 0/1", true, false },
			  { (void*) numbers, T_NUM, "n",	"Number of elements for inner product, default: 128", false, false },
			  {	(void*) bitlen, T_NUM, "b", "Bit-length, default 16", false, false },
			  { (void*) secparam, T_NUM, "s", "Symmetric Security Bits, default: 128", false, false },
			  {	(void*) address, T_STR, "a", "IP-address, default: localhost", false, false },
			  {	(void*) &int_port, T_NUM, "p", "Port, default: 7766", false, false },
			  { (void*) test_op, T_NUM, "t", "Single test (leave out for all operations), default: off",
					false, false } };

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

	return 1;
}

share* DecimalPlace(uint32_t bitlen, share* s_exponent, BooleanCircuit* circ){

	uint32_t zero = 0;
	share* s_temp = circ->PutCONSGate(zero, bitlen);
	share* s_move = circ->PutCONSGate(zero, bitlen);

	for(int i = 0;i<bitlen;i++){
		s_temp->set_wire_id(i,s_exponent->get_wire_id(bitlen-(i+1)));

	}


	for(int i = 0;i<8;i++){
		s_move->set_wire_id(i,s_temp->get_wire_id(8-i));
	}	

	return s_move;
}


int32_t test_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t numbers, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg,
		e_sharing sharing) {




	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads,
			mt_alg);


	std::vector<Sharing*>& sharings = party->GetSharings();


	
	BooleanCircuit* bool_circ =
			(BooleanCircuit*) sharings[S_BOOL]->GetCircuitBuildRoutine();


	//uint32_t N = 56;

    float N = 1.0;
	float M = 1.1;

    uint32_t *nptr = (uint32_t *) &N;
	uint32_t *mptr = (uint32_t *) &M;

	share* s_n = bool_circ -> PutCONSGate(nptr, bitlen);
    share* s_m = bool_circ -> PutCONSGate(mptr, bitlen);

	float A = 2.8235294;
	float B = 1.8823529;

	uint32_t *aptr = (uint32_t *) &A;
	uint32_t *bptr = (uint32_t *) &B;

	share* s_a = bool_circ -> PutCONSGate(aptr, bitlen);
	share* s_b = bool_circ -> PutCONSGate(bptr, bitlen);


	uint32_t a = 126;
	share* temp = bool_circ -> PutCONSGate(a, bitlen);

/*     for(uint32_t i = 0; i < 32; i++){

		bool_circ->PutPrintValueGate(s_n->get_wire_ids_as_share(i)," s_n is ");
	} */


    share* s_nDecimalPlace = DecimalPlace(bitlen, s_n, bool_circ);
    share* s_mDecimalPlace = DecimalPlace(bitlen, s_m, bool_circ);
	
/* 	for(uint32_t i = 0; i < 32; i++){

		bool_circ->PutPrintValueGate(temp1->get_wire_ids_as_share(i)," temp1 is ");
	} */
	//PutConvTypeGate

   
    for(uint32_t i = 0; i < 8; i++){

		//bool_circ->PutPrintValueGate(temp->get_wire_ids_as_share(i)," ssa is ");

        s_n -> set_wire_id(23+i, temp->get_wire_id(i));
	}

/* 	for(uint32_t i = 0; i < 32; i++){

		bool_circ->PutPrintValueGate(s_n->get_wire_ids_as_share(i)," s_n2 is ");
	} */

	share* s_nChangeDecimalPlace = DecimalPlace(bitlen, s_n, bool_circ);

	share* s_nDvalue = bool_circ->PutSUBGate(s_nDecimalPlace, s_nChangeDecimalPlace);

	share* s_mChangeDecimalPlace = bool_circ->PutSUBGate(s_mDecimalPlace, s_nDvalue);

	for(uint32_t i = 0; i < 8; i++){

		//bool_circ->PutPrintValueGate(s_mChangeDecimalPlace->get_wire_ids_as_share(i)," ssa is ");

        s_m -> set_wire_id(23+i, s_mChangeDecimalPlace->get_wire_id(i));
	}

	//temp1 ->set_bitlength(8);
/* 	for(uint32_t i = 0; i < 32; i++){

		bool_circ->PutPrintValueGate(temp->get_wire_ids_as_share(i)," temp1 is ");
	}
     */


	//share* x_0 = bool_circ->PutMULGate(s_b, s_n);

	//x_0 = bool_circ-> PutSUBGate(s_a, x_0);
	share* x_0 = bool_circ->PutFPGate(s_b, s_n, MUL, bitlen, 1);

	x_0 = bool_circ->PutFPGate(s_a, x_0, SUB, bitlen, 1);

	share* x_1 = x_0;
	float two = (float)2.0;
	uint32_t *twoptr = (uint32_t * )&two;
	share* s_two = bool_circ -> PutCONSGate(twoptr, bitlen);
	for(uint8_t i = 0; i < 3; i++){
		x_1 = bool_circ->PutFPGate(s_n, x_0, MUL, bitlen, 1);
		x_1 = bool_circ->PutFPGate(s_two, x_1, SUB, bitlen, 1);
		x_1 = bool_circ->PutFPGate(x_0, x_1, MUL, bitlen, 1);
		x_0 = x_1;
		//x_1 = bool_circ-> PutMULGate(x_0, bool_circ->PutSUBGate(s_two, bool_circ->PutMULGate(s_n, x_0)));
	} 

	share* s_out = bool_circ->PutFPGate(s_m, x_1, MUL, bitlen, 1);

    s_n = bool_circ -> PutOUTGate(s_n, ALL);
	s_m = bool_circ -> PutOUTGate(s_m, ALL);
	s_a = bool_circ -> PutOUTGate(s_a, ALL);
    s_b = bool_circ -> PutOUTGate(s_b, ALL);
	x_0 = bool_circ -> PutOUTGate(x_0, ALL);
    x_1 = bool_circ -> PutOUTGate(x_1, ALL);
	s_out = bool_circ -> PutOUTGate(s_out, ALL);

	party->ExecCircuit();

	uint32_t output1, output2;


	uint32_t *s_n_out = (uint32_t*) s_n->get_clear_value_ptr();
	uint32_t *s_m_out = (uint32_t*) s_m->get_clear_value_ptr();
	uint32_t *s_a_out = (uint32_t*) s_a->get_clear_value_ptr();
	uint32_t *s_b_out = (uint32_t*) s_b->get_clear_value_ptr();
	uint32_t *x_0_out = (uint32_t*) x_0->get_clear_value_ptr();
	uint32_t *x_1_out = (uint32_t*) x_1->get_clear_value_ptr();
	uint32_t *s_out_out = (uint32_t*) s_out->get_clear_value_ptr();




	float s_n_out1 = *((float*) s_n_out);
	float s_m_out1 = *((float*) s_m_out);
	float s_a_out1 = *((float*) s_a_out);
	float s_b_out1 = *((float*) s_b_out);
	float x_0_out1 = *((float*) x_0_out);
	float x_1_out1 = *((float*) x_1_out);
	float s_out_out1 = *((float*) s_out_out);
   


	std::cout << "\ns_n_out Result: " << s_n_out1 << std::endl;
	std::cout << "\ns_m_out Result: " << s_m_out1 << std::endl;
    std::cout << "\ns_a_out Result: " << s_a_out1 << std::endl;
	std::cout << "\ns_b_out Result: " << s_b_out1 << std::endl;
	std::cout << "\nx_0_out Result: " << x_0_out1 << std::endl;
	std::cout << "\nx_1_out Result: " << x_1_out1 << std::endl;
	std::cout << "\ns_out_out1 Result: " << s_out_out1 << std::endl;

	delete party;

	return 0;
}

int main(int argc, char** argv) {

	e_role role;
	uint32_t bitlen = 32, numbers = 128, secparam = 128, nthreads = 1;
	uint16_t port = 7766;
	std::string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;

	read_test_options(&argc, &argv, &role, &bitlen, &numbers, &secparam, &address, &port, &test_op);

	seclvl seclvl = get_sec_lvl(secparam);

	test_circuit(role, address, port, seclvl, numbers, bitlen, nthreads, mt_alg, S_BOOL);
	
	//std::cout <<  iip << " " << verip << std::endl;
	return 0;
}

