#ifndef __Decimal_Place_Float_H_
#define __Decimal_Place_Float_H_

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

share* Decimal_Place_Float(uint32_t bitlen, share* s_exponent, BooleanCircuit* circ);

#endif
