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

share* Binary_exponent_Float(ABYParty* party, share* s_exponent, BooleanCircuit* circ);

share* Exponent_Pos(uint32_t bitlen, uint32_t decimalplace, share* s_exponent, share* s_Integer_base, share* s_Decimal_base, BooleanCircuit* circ);

share* Exponent_Neg(uint32_t bitlen, uint32_t decimalplace, share* s_exponent, share* s_Decimal_base, BooleanCircuit* circ);

#endif
