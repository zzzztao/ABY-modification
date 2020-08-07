#include "Decimal_Place_Float.h"

using namespace std;

share* Decimal_Place_Float(uint32_t bitlen, share* s_exponent, BooleanCircuit* circ){

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


