#ifndef __GROWTH_INDEX_H_
#define __GROWTH_INDEX_H_

#include <ENCRYPTO_utils/crypto/crypto.h>
#include<ENCRYPTO_utils/parse_options.h>


#include "../../abycore/aby/abyparty.h"
#include "../../abycore/circuit/booleancircuits.h"
#include "../../abycore/circuit/arithmeticcircuits.h"
#include "../../abycore/circuit/circuit.h"
#include "../../abycore/circuit/share.h"
#include "../../abycore/sharing/sharing.h"
#include <math.h>
#include <cassert>

#define ALICE 	"ALICE"
#define BOB 	"BOB"

int32_t Binary_exponent(e_role role, const std::string& address, uint16_t port, seclvl seclvl, uint32_t nvals, uint32_t bitlen,
		uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing);

share* DecimalPlace(uint32_t bitlen, uint32_t nvals, share* s_test, BooleanCircuit* circ);

share* BuildTestCircuit_Pos(uint32_t bitlen, uint32_t nvals, uint32_t decimalplace, share* s_test_a, share* s_test_b, share* s_test_c, BooleanCircuit* circ);

share* BuildTestCircuit_Neg(uint32_t bitlen, uint32_t nvals, uint32_t decimalplace, share* s_test_a, share* s_test_b, share* s_test_c, BooleanCircuit* circ);

#endif
