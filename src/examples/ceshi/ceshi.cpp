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


int32_t test_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t numbers, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg,
		e_sharing sharing) {




	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads,
			mt_alg);


	std::vector<Sharing*>& sharings = party->GetSharings();


	
	BooleanCircuit* bool_circ =
			(BooleanCircuit*) sharings[S_BOOL]->GetCircuitBuildRoutine();

	ArithmeticCircuit* Arith_circ = (ArithmeticCircuit*) sharings[S_ARITH]->GetCircuitBuildRoutine();

	uint32_t arith[1000], arith_mul = 1, aa = 33;

	//float bb= 8.5;
	//uint32_t *bbptr = (uint32_t * )&bb;

	//share* ab = bool_circ ->PutINGate(aa, bitlen, SERVER);
	//share* ac = bool_circ ->PutSIMDINGate(1, bbptr, bitlen, CLIENT);
	//share* n = bool_circ ->PutINGate(arith_mul, bitlen, CLIENT);

	//share* lab = bool_circ ->PutBarrelLeftShifterGate(ac,  n);
	//share* rab = bool_circ ->PutBarrelRightShifterGate(ac, n);

	//bool_circ ->PutConvTypeGate(ab, uint32_t, double, 1);

	//share* cc = bool_circ ->PutFPGate(ac,ab,MUL,bitlen,1);

	share* s_arith_mul = Arith_circ->PutINGate(arith_mul, bitlen, SERVER);
	srand((uint)time(0));

	for(int i = 0; i < 10; i++){
		arith[i] = 2;
		//rand() % 1000;
		//std::cout << arith[i] <<std::endl;
				//rand() % 10;
		
		share* temp = Arith_circ->PutINGate(arith[i], bitlen, CLIENT);
		s_arith_mul = Arith_circ->PutMULGate(temp , s_arith_mul);
	}


	s_arith_mul = Arith_circ->PutOUTGate(s_arith_mul, ALL);
 

	/*bitlen = 16;
	uint16_t a = 5, b = 5, c = 6, d = 61;

	share* a_bool = bool_circ->PutINGate(a, bitlen, SERVER); 
	share* c_bool = bool_circ->PutINGate(c, bitlen, SERVER); 
	share* b_bool = bool_circ->PutINGate(b, bitlen, CLIENT); 
	share* d_bool = bool_circ->PutINGate(d, bitlen, CLIENT); 

	share* gt_bool = bool_circ->PutGTGate(bool_circ->PutMULGate(bool_circ->PutADDGate(a_bool, b_bool), c_bool), d_bool);*/
     
	//cc = bool_circ->PutOUTGate(cc, ALL);
	//lab = bool_circ->PutOUTGate(lab, ALL);
	//rab = bool_circ->PutOUTGate(rab, ALL);


	
	party->ExecCircuit();

	uint32_t gt_bool_out, output , llab, rrab;
	uint32_t arith_out;

	//gt_bool_out = cc->get_clear_value<uint32_t>();
	//llab = lab->get_clear_value<uint32_t>();
	//rrab = rab->get_clear_value<uint32_t>();	

	//std::cout << "\nPutBarrelLeftShifterGate: " << llab << std::endl;
	
	//std::cout << "\nPutBarrelRightShifterGate: " << rrab << std::endl;

	arith_out = s_arith_mul->get_clear_value<uint32_t>();
	//std::cout << "\nCircuit Result: " << gt_bool_out << std::endl;
	
	std::cout << "\nArithMul Result: " << arith_out << std::endl;
	delete party;

	return 0;
}

int main(int argc, char** argv) {

	e_role role;
	uint32_t bitlen = 32, numbers = 128, secparam = 128, nthreads = 1;
	uint16_t port = 7766;
	std::string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_PAILLIER;

	read_test_options(&argc, &argv, &role, &bitlen, &numbers, &secparam, &address, &port, &test_op);

	seclvl seclvl = get_sec_lvl(secparam);

	test_circuit(role, address, port, seclvl, numbers, bitlen, nthreads, mt_alg, S_BOOL);
	
	//std::cout <<  iip << " " << verip << std::endl;
	return 0;
}

