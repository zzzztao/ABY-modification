#include "Decimal_Place_Float.h"

using namespace std;

share* Decimal_Place_Float(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
			     uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, share* s_exponent, BooleanCircuit* bc1){

	for(uint32_t i = 0; i < 32; i++){

		//cout << s_exponent->get_wire_id(i) <<endl;

		bc1->PutPrintValueGate(s_exponent->get_wire_ids_as_share(i)," s_exponent02 is ");
	}
	
	
	
	ABYParty* party1 = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);
	vector<Sharing*>& sharings = party1->GetSharings();
	BooleanCircuit* circ = (BooleanCircuit*) sharings[S_BOOL]->GetCircuitBuildRoutine();


	cout<<"子电路s_exponent："<< &s_exponent <<endl;
	float t_exponent = 1;
	
	uint32_t* pptr  = (uint32_t*)&t_exponent;
	share* s_tem = circ->PutCONSGate(*pptr, bitlen);
	//s_tem = s_exponent;

	circ->PutPrintValueGate(s_tem," s_exponent02 is ");
	

	share* s_temp = DecimalPlace(bitlen, s_tem, circ);//得出小数点的偏移量

	share* s_out = circ->PutOUTGate(s_temp,ALL);
	party1->ExecCircuit();
	uint32_t out = s_out->get_clear_value<uint32_t>();
	cout<<"子电路偏移量："<<out<<endl;
	//delete party;
	return s_temp;

	
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

