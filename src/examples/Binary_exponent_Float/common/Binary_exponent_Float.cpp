#include "Binary_exponent_Float.h"

using namespace std;

share* Binary_exponent_Float(ABYParty* party, share* s_exponent, BooleanCircuit* circ){

	uint32_t bitlen = 32;

	uint32_t out_bitlen, out_nvals, dp;
	uint32_t *out_vals;
	
	float f_Integer_base[4] = {2.718281846,7.389056098,54.598150033,2980.957987041};//{e^1,e^2,e^4,e^8}
	float f_Decimal_base[6] = {1.648721270,1.284025417,1.133148453,1.064494459,1.031743407,1.015747709};//{e^1/2,e^1/4,e^1/8,e^1/16,e^1/32,e^1/64}

	uint32_t Integer_base[4], Decimal_base[6];
	for(int i=0;i<4;i++)
		Integer_base[i] = *((uint32_t*) &f_Integer_base[i]);
	for(int i=0;i<6;i++)
		Decimal_base[i] = *((uint32_t*) &f_Decimal_base[i]);
		//cout<<"test3["<<i<<"] is "<<fixed<< setprecision(5) <<*(float*) &test3[i]<<endl;
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	//share* s_Integer_base = circ->PutSIMDCONSGate(4, Integer_base, bitlen);
	/*share* s_Decimal_base = circ->PutSIMDCONSGate(6, Decimal_base, bitlen);
	share* s_out;

	//当整数位不为0时
	if(dp>127){
		dp -= 127;//小数点最终的偏移值
		
		s_out = Exponent_Pos(bitlen, dp, s_exponent, s_Integer_base, s_Decimal_base, (BooleanCircuit*) circ);
	}

	//当整数位为0时
	else{
		dp = 127-dp;//小数点最终的偏移值

		s_out = Exponent_Neg(bitlen, dp, s_exponent, s_Decimal_base, (BooleanCircuit*) circ);
	}*/

	return s_exponent;
}

share* Exponent_Pos(uint32_t bitlen, uint32_t decimalplace, share* s_exponent, share* s_Integer_base, share* s_Decimal_base, BooleanCircuit* circ){

	uint32_t zero = 0;
	uint32_t one = 1;
	float f_zero = 0;
	float f_one = 1;
	uint32_t *i_zero = (uint32_t*) &f_zero;
	uint32_t *i_one = (uint32_t*) &f_one;

	share* reversal = circ->PutCONSGate(zero, bitlen);
	share* integer = circ->PutCONSGate(one, bitlen);
	share* decimal = circ->PutCONSGate(zero, bitlen);
	share* in_result = circ->PutCONSGate(*i_one, bitlen);
	share* de_result = circ->PutCONSGate(*i_one, bitlen);
	share* s_zero = circ->PutCONSGate(zero, bitlen);
	share* s_one = circ->PutCONSGate(one, bitlen);
	share* s_f_zero = circ->PutCONSGate(*i_zero, bitlen);
	share* s_f_one = circ->PutCONSGate(*i_one, bitlen);
	share* temp = circ->PutCONSGate(*i_one, bitlen);
	share *temp1, *temp2, *temp3, *temp4, *s_cmp, *result, *rec_result, *fin_result;

	//将整体2进制反转
	for(int i = 0;i<bitlen;i++){
		reversal->set_wire_id(i,s_exponent->get_wire_id(bitlen-(i+1)));
	}
	
	//获得整数部分2进制
	for(int i = 0;i<decimalplace;i++){
		integer->set_wire_id(i,reversal->get_wire_id(8+decimalplace-i));
	}
	integer->set_wire_id(decimalplace, s_one->get_wire_id(0));


	//获得小数部分2进制
	for(int i = 0;i<6;i++){
		decimal->set_wire_id(i,reversal->get_wire_id(9+decimalplace+i));
	}

	for(int i = 0;i<4;i++){

		temp1 = circ->PutCombineAtPosGate(s_Integer_base , i);//取出整数基底中的第i个nval并转为单线（32nval，1bit）
		temp2 = circ->PutSplitterGate(temp1);//转化为多线（1nval，32bit）
		temp3 = integer->get_wire_ids_as_share(i);//获取整数部分的2进制（4位）
		s_cmp = circ->PutGTGate(temp3, s_zero);
		temp3 = circ->PutMUXGate( s_f_one, s_f_zero, s_cmp);
		temp4 = circ->PutFPGate(temp2, temp3, MUL);//按位与基底相乘
		s_cmp = circ->PutGTGate(temp4, s_zero);//判断结果是否大于0
		temp = circ->PutMUXGate(temp4, s_f_one, s_cmp);//若大于0则返回自身，否则返回1
		in_result = circ->PutFPGate(in_result, temp, MUL);//类乘得到整数部分的最终结果
	}

	for(int i = 0;i<6;i++){

		temp1 = circ->PutCombineAtPosGate(s_Decimal_base , i);//取出小数基底中的第i个nval并转为单线（32nval，1bit）
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

share* Exponent_Neg(uint32_t bitlen, uint32_t decimalplace, share* s_exponent, share* s_Decimal_base, BooleanCircuit* circ){

	uint32_t zero = 0;
	uint32_t one = 1;
	float f_zero = 0;
	float f_one = 1;
	uint32_t *i_zero = (uint32_t*) &f_zero;
	uint32_t *i_one = (uint32_t*) &f_one;

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
		reversal->set_wire_id(i, s_exponent->get_wire_id(bitlen-(i+1)));
	}

	//获得小数部分2进制	
	decimal->set_wire_id(decimalplace-1,s_one->get_wire_id(0));

	for(int i = 0;i<6-decimalplace;i++){
		decimal->set_wire_id(decimalplace+i,reversal->get_wire_id(9+i));
	}

	temp1 = reversal->get_wire_ids_as_share(0);
	circ->PutPrintValueGate(temp1,"符号位是 ");

	for(int i = 0;i<6;i++){

		temp1 = circ->PutCombineAtPosGate(s_Decimal_base , i);//取出小数基底中的第i个nval并转为单线（32nval，1bit）
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
