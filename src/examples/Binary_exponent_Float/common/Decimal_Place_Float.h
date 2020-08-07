#ifndef __GROWTH_INDEX_H_
#define __GROWTH_INDEX_H_

#include <ENCRYPTO_utils/crypto/crypto.h>
#include<ENCRYPTO_utils/parse_options.h>


#include "../../../abycore/aby/abyparty.h"
#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/circuit/arithmeticcircuits.h"
#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/circuit/share.h"
#include "../../../abycore/sharing/sharing.h"
#include <math.h>
#include <iomanip>
#include <cassert>

#define ALICE 	"ALICE"
#define BOB 	"BOB"

share* Decimal_Place_Float(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
			     uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing, share* s_exponent, BooleanCircuit* circ);

share* DecimalPlace(uint32_t bitlen, share* s_exponent, BooleanCircuit* circ);

#endif
