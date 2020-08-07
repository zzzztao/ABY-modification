#include <ENCRYPTO_utils/crypto/crypto.h>
#include<ENCRYPTO_utils/parse_options.h>

#include "../../abycore/aby/abyparty.h"
#include "common/Decimal_Place_Float.h"
#include "common/Binary_exponent_Float.h"

using namespace std;

int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role,
		uint32_t* bitlen, uint32_t* nvals, uint32_t* secparam, std::string* address,
		uint16_t* port, int32_t* test_op) {

	uint32_t int_role = 0, int_port = 0;
	bool useffc = false;

	parsing_ctx options[] ={ 
				{ (void*) &int_role, T_NUM, "r", "Role: 0/1", true, false }, 
				{(void*) nvals, T_NUM, "n","Number of parallel operation elements", false, false }, 		
				{(void*) bitlen, T_NUM, "b", "Bit-length, default 32", false,false }, 
				{(void*) secparam, T_NUM, "s","Symmetric Security Bits, default: 128", false, false }, 
				{(void*) address, T_STR, "a","IP-address, default: localhost", false, false }, 
				{(void*) &int_port, T_NUM, "p", "Port, default: 7766", false,false }, 
				{ (void*) test_op, T_NUM, "t","Single test (leave out for all operations), default:off",false, false } 


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


	return 1;
}

int32_t test_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
			     uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing){

	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);
	vector<Sharing*>& sharings = party->GetSharings();
	BooleanCircuit* circ = (BooleanCircuit*) sharings[S_BOOL]->GetCircuitBuildRoutine();

	uint32_t out_bitlen, out_nvals, one = 1;
	uint64_t *out_vals;
	
	float f_exponent = 6.14;
	uint32_t *i_exponent = (uint32_t*) &f_exponent;
	share* s_exponent = circ->PutCONSGate(*i_exponent, bitlen);
	//share* s_exponent = circ->PutCONSGate(one, bitlen);
	//circ->PutPrintValueGate(s_exponent,"s_exponent is ");
	cout<<"主电路s_exponent："<< &s_exponent <<endl;
	for(int  i = 0; i < 32; i++){

		cout << "111" <<endl;

		circ->PutPrintValueGate(s_exponent->get_wire_ids_as_share(i)," s_exponent01 is ");
	}
	
	
	//uint32_t** pptr = (uint32_t**)&s_exponent;
	port = 7767;
	share* dp = Decimal_Place_Float(role, address, port, seclvl, bitlen, nthreads, mt_alg, sharing, s_exponent, circ);
	//share* dp = Decimal_Place_Float(role, address, port, seclvl, bitlen, nthreads, mt_alg, sharing, s_exponent);
	//cout<<"dp是："<<dp<<endl;
	cout<<"测试："<<endl;
	//share* s_out = Binary_exponent_Float(party, s_exponent, circ);

	share* s_out = circ->PutOUTGate(dp,ALL);
	party->ExecCircuit();
	
	/*uint32_t* out = (uint32_t*) s_out->get_clear_value_ptr();
	float val = *((float*) out);
	cout<<"finall is "<<val<<endl;*/

	uint32_t out = s_out->get_clear_value<uint32_t>();
	cout<<"主电路偏移量："<<out<<endl;

	return 0;

}

int main(int argc, char** argv) {

	e_role role;
	uint32_t bitlen = 32, secparam = 128, nthreads = 1, nvals = 32;
	uint16_t port = 7766;
	std::string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;

	read_test_options(&argc, &argv, &role, &bitlen, &nvals, &secparam, &address,
			&port, &test_op);

	seclvl seclvl = get_sec_lvl(secparam);
	
	test_circuit(role, address, port, seclvl, bitlen, nthreads, mt_alg, S_YAO);


	return 0;
}
