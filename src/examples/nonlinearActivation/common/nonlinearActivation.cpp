/**
 \file 		nonlinearActivation_test.cpp
 \author	zzzztao
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
//ABY Party class
#include "../../../abycore/sharing/sharing.h"

#include "nonlinearActivation.h"




share* sigmoid(uint32_t bitlen, share* s_n, BooleanCircuit* circ){
	//x范围[-3, 3]
	float positiveThree = 3.0;
	float minusThree = -3.0;

	uint32_t *positiveThreeptr = (uint32_t *) &positiveThree;
	uint32_t *minusThreeptr = (uint32_t *) &minusThree;

	share* s_positiveThree = circ -> PutCONSGate(positiveThreeptr, bitlen);
	share* s_minusThree = circ -> PutCONSGate(minusThreeptr, bitlen);

	float positiveOne = 1.0;
	float positiveZero = 0.0;

	uint32_t *positiveOneptr = (uint32_t *) &positiveOne;
	uint32_t *positiveZeroptr = (uint32_t *) &positiveZero;

	share* s_positiveOne = circ -> PutCONSGate(positiveOneptr, bitlen);
	share* s_positiveZero = circ -> PutCONSGate(positiveZeroptr, bitlen);

	//int one = 1;
	//share* s_one = circ -> PutCONSGate(one, bitlen);
	//s_n->set_wire_id(31,circ->PutMUXGate(s_one->get_wire_id(1), s_one->get_wire_id(0), s_n->get_wire_id(31)));
	
	//计算-x
	share* s_n_inv = circ -> PutFPGate(s_positiveZero, s_n, SUB);
	//x属于[-3, 3]时计算指数
	share* res = circ -> PutMUXGate(s_positiveOne, circ -> PutMUXGate(circ -> PutFPGate(s_n_inv, EXP), s_positiveZero, circ -> PutFPGate(s_n_inv, s_minusThree, CMP)), circ -> PutFPGate(s_n_inv, s_positiveThree, CMP));
	
	res->set_bitlength(bitlen);

	return res;
	
		
}

share* tanh(uint32_t bitlen, share* s_n, BooleanCircuit* circ){

	float consTwo = 2.0;
	uint32_t *consTwoPtr = (uint32_t *) &consTwo;
	share* s_consTwo = circ -> PutCONSGate(consTwoPtr, bitlen);

	float consOne = 1.0;
	uint32_t *consOnePtr = (uint32_t *) &consOne;
	share* s_consOne = circ -> PutCONSGate(consOnePtr, bitlen);

	share* double_s_n = circ -> PutFPGate(s_n, s_consTwo, MUL);

	share* res = circ -> PutFPGate(circ -> PutFPGate(sigmoid(bitlen, double_s_n, circ), s_consTwo, MUL), s_consOne, SUB);

	return res;
		
}

int32_t test_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t numbers, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg,
		e_sharing sharing) {

	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);

	std::vector<Sharing*>& sharings = party->GetSharings();
	
	BooleanCircuit* bool_circ = (BooleanCircuit*) sharings[S_BOOL]->GetCircuitBuildRoutine();

	float test1 = -2.0;
	float test2 = 2.0;

    uint32_t *test1ptr = (uint32_t *) &test1;
	uint32_t *test2ptr = (uint32_t *) &test2;

	share* s_test1 = bool_circ -> PutCONSGate(test1ptr, bitlen);
	share* s_test2 = bool_circ -> PutCONSGate(test2ptr, bitlen);

	share* s_sigmoid_test1out = sigmoid(bitlen, s_test1, bool_circ);
	share* s_sigmoid_test2out = sigmoid(bitlen, s_test2, bool_circ);

	share* s_tanh_test1out = tanh(bitlen, s_test1, bool_circ);
	share* s_tanh_test2out = tanh(bitlen, s_test2, bool_circ);

	s_sigmoid_test1out = bool_circ->PutOUTGate(s_sigmoid_test1out, ALL);
	s_sigmoid_test2out = bool_circ->PutOUTGate(s_sigmoid_test2out, ALL);

	s_tanh_test1out = bool_circ->PutOUTGate(s_tanh_test1out, ALL);
	s_tanh_test2out = bool_circ->PutOUTGate(s_tanh_test2out, ALL);
	
	party->ExecCircuit();

	uint32_t *sigmoid_test1outptr = (uint32_t*) s_sigmoid_test1out->get_clear_value_ptr();
	float sigmoid_test1out = *((float*) sigmoid_test1outptr);

	uint32_t *sigmoid_test2outptr = (uint32_t*) s_sigmoid_test2out->get_clear_value_ptr();
	float sigmoid_test2out = *((float*) sigmoid_test2outptr);

	std::cout << "\nsigmoid_test1 Result: " << sigmoid_test1out << std::endl;
	std::cout << "\nsigmoid_test2 Result: " << sigmoid_test2out << std::endl; 

	uint32_t *tanh_test1outptr = (uint32_t*) s_tanh_test1out->get_clear_value_ptr();
	float tanh_test1out = *((float*) tanh_test1outptr);

	uint32_t *tanh_test2outptr = (uint32_t*) s_tanh_test2out->get_clear_value_ptr();
	float tanh_test2out = *((float*) tanh_test2outptr);

	std::cout << "\ntanh_test1 Result: " << tanh_test1out << std::endl; 
	std::cout << "\ntanh_test1 Result: " << tanh_test2out << std::endl;   
	
	delete party;

	return 0;
}