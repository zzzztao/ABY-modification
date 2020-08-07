
#include "Binary_exponent_Double.h"
#include <iomanip>

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

int32_t Binary_exponent(e_role role, const std::string& address, uint16_t port, seclvl seclvl, uint32_t nvals, uint32_t bitlen,
		uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing){
	
	ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);

	vector<Sharing*>& sharings = party->GetSharings();

	BooleanCircuit* circ = (BooleanCircuit*) sharings[S_BOOL]->GetCircuitBuildRoutine();
	ArithmeticCircuit* ac =	(ArithmeticCircuit*) sharings[S_ARITH]->GetCircuitBuildRoutine();

	uint32_t out_bitlen, out_nvals;
	uint64_t *out_vals;
	
	double f_test1 = -3.14;
	double f_test2[4] = {2.718281846,7.389056098,54.598150033,2980.957987041};//{e^1,e^2,e^4,e^8}
	double f_test3[6] = {1.648721270,1.284025417,1.133148453,1.064494459,1.031743407,1.015747709};//{e^1/2,e^1/4,e^1/8,e^1/16}

	uint64_t* test1 = (uint64_t*) &f_test1;
	uint64_t test2[4], test3[6];
	for(int i=0;i<4;i++)
		test2[i] = *((uint64_t*) &f_test2[i]);
	for(int i=0;i<6;i++)
		test3[i] = *((uint64_t*) &f_test3[i]);
		//cout<<"test3["<<i<<"] is "<<fixed<< setprecision(5) <<*(float*) &test3[i]<<endl;

	share* s_test = circ->PutINGate(test1, bitlen, SERVER);
	
	share* s_dp = DecimalPlace(bitlen, nvals, s_test, (BooleanCircuit*) circ);//得出小数点的偏移量
	s_dp = circ->PutOUTGate(s_dp, ALL);

	party->ExecCircuit();	
	
	uint64_t dp = s_dp->get_clear_value<uint64_t>();

	party->Reset();
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	share* s_test1 = circ->PutINGate(test1, bitlen, SERVER);
	share* s_test2 = circ->PutSIMDINGate(4, test2, bitlen, SERVER);
	share* s_test3 = circ->PutSIMDINGate(6, test3, bitlen, SERVER);
	share* s_out;
	//当整数位不为0时
	if(dp>1023){
		dp -= 1023;//小数点最终的偏移值
		cout<<"pos_dp is "<<dp<<endl;
		
		s_out = BuildTestCircuit_Pos(bitlen, nvals, dp, s_test1, s_test2, s_test3, (BooleanCircuit*) circ);
	}

	//当整数位为0时
	else{
		dp = 1023-dp;//小数点最终的偏移值
		cout<<"neg_dp is "<<dp<<endl;
		
		s_out = BuildTestCircuit_Neg(bitlen, nvals, dp, s_test1, s_test2, s_test3, (BooleanCircuit*) circ);
	}

	s_out = circ->PutOUTGate(s_out, ALL);
	
	party->ExecCircuit();	

	s_out->get_clear_value_vec(&out_vals, &out_bitlen, &out_nvals);

	for(int i=0;i<out_nvals;i++){
		//uint64_t val = out_vals[i];
		double val = *((double*) &out_vals[i]);
		cout<< "va"<< i <<" is: "<<fixed<< setprecision(5) << val <<endl;
		
	}
	
	/*uint32_t out = s_out->get_clear_value<uint32_t>();
	cout<<"out is "<<out<<endl;*/

	/*uint32_t* out = (uint32_t*) s_out->get_clear_value_ptr();
	float val = *((float*) out);
	cout<<"out is "<<val<<endl;*/

	return 0;

}

share* DecimalPlace(uint32_t bitlen, uint32_t nvals, share* s_test, BooleanCircuit* circ){

	uint64_t one = 0;
	share* s_temp = circ->PutCONSGate(one, bitlen);
	share* s_move = circ->PutCONSGate(one, bitlen);

	for(int i = 0;i<bitlen;i++){
		s_temp->set_wire_id(i,s_test->get_wire_id(bitlen-(i+1)));
		//share* temp1 = s_test->get_wire_ids_as_share(i);
		//circ->PutPrintValueGate(temp1,"temp1 is ");
	}


	for(int i = 0;i<11;i++){
		s_move->set_wire_id(i,s_temp->get_wire_id(11-i));
		//share* temp1 = s_move->get_wire_ids_as_share(i);
		//circ->PutPrintValueGate(temp1,"temp1 is ");
	}	

	return s_move;
}

share* BuildTestCircuit_Pos(uint32_t bitlen, uint32_t nvals, uint32_t decimalplace, share* s_test_a, share* s_test_b, share* s_test_c, BooleanCircuit* circ){

	uint64_t zero = 0;
	uint64_t one = 1;
	double f_zero = 0;
	double f_one = 1;
	uint64_t *i_one = (uint64_t*) &f_one;
	uint64_t *i_zero = (uint64_t*) &f_zero;
	share* reversal = circ->PutCONSGate(zero, bitlen);
	share* integer = circ->PutCONSGate(one, bitlen);
	share* decimal = circ->PutCONSGate(zero, bitlen);
	share* in_result = circ->PutCONSGate(*i_one, bitlen);
	share* de_result = circ->PutCONSGate(*i_one, bitlen);
	share* s_zero = circ->PutCONSGate(zero, bitlen);
	share* s_one = circ->PutCONSGate(one, bitlen);
	share* s_f_one = circ->PutCONSGate(*i_one, bitlen);
	share* s_f_zero = circ->PutCONSGate(*i_zero, bitlen);
	share* temp = circ->PutCONSGate(*i_one, bitlen);
	share *temp1, *temp2, *temp3, *temp4, *s_cmp, *result, *rec_result, *fin_result;

	//将整体2进制反转
	for(int i = 0;i<bitlen;i++){
		reversal->set_wire_id(i,s_test_a->get_wire_id(bitlen-(i+1)));
	}
	
	//获得整数部分2进制
	for(int i = 0;i<decimalplace;i++){
		integer->set_wire_id(i,reversal->get_wire_id(11+decimalplace-i));
	}
	integer->set_wire_id(decimalplace, s_one->get_wire_id(0));


	//获得小数部分2进制
	for(int i = 0;i<6;i++){
		decimal->set_wire_id(i,reversal->get_wire_id(12+decimalplace+i));
	}
	//temp1 = integer->get_wire_ids_as_share(3);
	//circ->PutPrintValueGate(temp1,"integer is ");
	//输出排错
	/*for(int i = 0;i<4;i++){
		temp1 = integer->get_wire_ids_as_share(i);
		circ->PutPrintValueGate(temp1,"integer is ");
	}*/

	for(int i = 0;i<4;i++){

		temp1 = circ->PutCombineAtPosGate(s_test_b , i);//取出整数基底中的第i个nval并转为单线（32nval，1bit）
		temp2 = circ->PutSplitterGate(temp1);//转化为多线（1nval，32bit）
		temp3 = integer->get_wire_ids_as_share(i);//获取整数部分的2进制（4位）
		s_cmp = circ->PutGTGate(temp3, s_zero);
		temp3 = circ->PutMUXGate( s_f_one, s_f_zero, s_cmp);
		temp4 = circ->PutFPGate(temp2, temp3,MUL);//按位与基底相乘
		s_cmp = circ->PutGTGate(temp4, s_zero);//判断结果是否大于0
		temp = circ->PutMUXGate(temp4, s_f_one, s_cmp);//若大于0则返回自身，否则返回1
		in_result = circ->PutFPGate(in_result, temp, MUL);//类乘得到整数部分的最终结果
	}

	for(int i = 0;i<6;i++){

		temp1 = circ->PutCombineAtPosGate(s_test_c , i);//取出小数基底中的第i个nval并转为单线（32nval，1bit）
		temp2 = circ->PutSplitterGate(temp1);//转化为多线（1nval，32bit）
		temp3 = decimal->get_wire_ids_as_share(i);//获取小数部分的2进制（4位）
		s_cmp = circ->PutGTGate(temp3, s_zero);
		temp3 = circ->PutMUXGate( s_f_one, s_f_zero, s_cmp);
		temp4 = circ->PutFPGate(temp2, temp3, MUL);//按位与基底相乘
		s_cmp = circ->PutGTGate(temp4, s_zero);//判断结果是否大于0
		temp = circ->PutMUXGate(temp4, s_f_one, s_cmp);//若大于0则返回自身，否则返回1
		de_result = circ->PutFPGate(de_result, temp, MUL);//类乘得到小数部分的最终结果
	}

	result = circ->PutFPGate(in_result, de_result, MUL);

	rec_result = circ->PutFPGate(s_f_one, result, DIV);

	temp = reversal->get_wire_ids_as_share(0);
	s_cmp = circ->PutGTGate(temp, s_zero);

	fin_result = circ->PutMUXGate(rec_result, result, s_cmp);

	return fin_result;
}

share* BuildTestCircuit_Neg(uint32_t bitlen, uint32_t nvals, uint32_t decimalplace, share* s_test_a, share* s_test_b, share* s_test_c, BooleanCircuit* circ){

	uint64_t zero = 0;
	uint64_t one = 1;
	double f_zero = 0;
	double f_one = 1;
	uint64_t *i_zero = (uint64_t*) &f_zero;
	uint64_t *i_one = (uint64_t*) &f_one;
	share* reversal = circ->PutCONSGate(zero, bitlen);
	share* decimal = circ->PutCONSGate(zero, bitlen);
	share* de_result = circ->PutCONSGate(*i_one, bitlen);
	share* s_zero = circ->PutCONSGate(zero, bitlen);
	share* s_one = circ->PutCONSGate(one, bitlen);
	share* s_f_zero = circ->PutCONSGate(*i_zero, bitlen);
	share* s_f_one = circ->PutCONSGate(*i_one, bitlen);
	share* temp = circ->PutCONSGate(*i_one, bitlen);
	share *temp1, *temp2, *temp3, *temp4, *s_cmp, *result, *rec_result, *fin_result;

	//将整体2进制反转
	for(int i = 0;i<bitlen;i++){
		reversal->set_wire_id(i,s_test_a->get_wire_id(bitlen-(i+1)));
	}

	//获得小数部分2进制	
	decimal->set_wire_id(decimalplace-1,s_one->get_wire_id(0));

	for(int i = 0;i<6-decimalplace;i++){
		decimal->set_wire_id(decimalplace+i,reversal->get_wire_id(12+i));
	}

	temp1 = reversal->get_wire_ids_as_share(0);
	circ->PutPrintValueGate(temp1,"符号位是 ");

	/*temp1 = decimal->get_wire_ids_as_share(3);
	circ->PutPrintValueGate(temp1,"decimal are ");*/

	//输出排错
	/*for(int i = 0;i<6;i++){
		temp1 = decimal->get_wire_ids_as_share(i);
		circ->PutPrintValueGate(temp1,"decimal is ");
	}*/

	for(int i = 0;i<6;i++){

		temp1 = circ->PutCombineAtPosGate(s_test_c , i);//取出小数基底中的第i个nval并转为单线（32nval，1bit）
		temp2 = circ->PutSplitterGate(temp1);//转化为多线（1nval，32bit）
		temp3 = decimal->get_wire_ids_as_share(i);//获取小数部分的2进制（4位）
		s_cmp = circ->PutGTGate(temp3, s_zero);
		temp3 = circ->PutMUXGate( s_f_one, s_f_zero, s_cmp);
		temp4 = circ->PutFPGate(temp2, temp3, MUL);//按位与基底相乘
		s_cmp = circ->PutGTGate(temp4, s_zero);//判断结果是否大于0
		temp = circ->PutMUXGate(temp4, s_f_one, s_cmp);//若大于0则返回自身，否则返回1
		de_result = circ->PutFPGate(de_result, temp, MUL);//类乘得到小数部分的最终结果
	}

	result = de_result;

	rec_result = circ->PutFPGate(s_f_one, result, DIV);

	temp = reversal->get_wire_ids_as_share(0);
	s_cmp = circ->PutGTGate(temp, s_zero);

	fin_result = circ->PutMUXGate(rec_result, result, s_cmp);

	return fin_result;
}


int main(int argc, char** argv) {

	e_role role;



	uint32_t bitlen = 64, secparam = 128, nthreads = 1, nvals = 8;
	uint16_t port = 7766;
	std::string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;

	read_test_options(&argc, &argv, &role, &bitlen, &nvals, &secparam, &address,
			&port, &test_op);

	seclvl seclvl = get_sec_lvl(secparam);
	
	Binary_exponent(role, address, port, seclvl, nvals, bitlen, nthreads, mt_alg, S_YAO);


	return 0;
}
