/**
 \file 		djnparty.cpp
 \author 	daniel.demmler@ec-spride.de
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
 \brief		Implementation of DJNParty class
 */

#include "djnparty.h"
#include "iostream"
#include <time.h>
#include <random>
#include <fstream>
#include <iostream>



/**
 * initializes a DJN_Party with the asymmetric security parameter and the shareBitLength.
 * Generates DJN key.
 * Key Exchange must be done manually after calling this constructor!
 */
DJNParty::DJNParty(uint32_t DJNModulusBits, uint32_t shareBitLength, channel* chan) {

	m_nShareBitLength = shareBitLength;
	m_nDJNModulusBits = DJNModulusBits;
	m_nBuflen = DJNModulusBits / 4 + 1;

//#if DJN_DEBUG
	std::cout << "(sock) Created party with " << DJNModulusBits << " bits and" << m_nBuflen << std::endl;
//#endif

	keyGen();
	keyExchange(chan);
}

DJNParty::DJNParty(uint32_t DJNModulusBits, uint32_t shareBitLength) {

	m_nShareBitLength = shareBitLength;
	m_nDJNModulusBits = DJNModulusBits;
	m_nBuflen = DJNModulusBits / 4 + 1;

//#if DJN_DEBUG
	std::cout << "(nosock) Created party with " << DJNModulusBits << " bits and" << m_nBuflen << std::endl;
//#endif

	keyGen();
}

void DJNParty::keyGen() {
#if DJN_DEBUG
	std::cout << "KG" << std::endl;
#endif
	djn_keygen(m_nDJNModulusBits, &m_localpub, &m_prv);
}

void DJNParty::setShareBitLength(uint32_t shareBitLength) {
	m_nShareBitLength = shareBitLength;
}

/**
 * deletes party and frees keys and randstate
 */
DJNParty::~DJNParty() {
#if DJN_DEBUG
	std::cout << "Deleting DJNParty...";
#endif
	djn_freeprvkey(m_prv);
	djn_freepubkey(m_localpub);
	djn_freepubkey(m_remotepub);
}

/**
 * inputs: pre-allocates byte buffers for aMT calculation.
 * numMTs is total number of MTs
 */
void DJNParty::computeArithmeticMTs(BYTE * bA, BYTE * bB, BYTE * bC, BYTE * bA1, BYTE * bB1, BYTE * bC1, uint32_t numMTs, channel* chan) {
	struct timespec start, end;
	numMTs = ceil_divide(numMTs, 2); // We can be both sender and receiver at the same time.
	//uint32_t vertorLength = numMTs * 4;
	//m_nDJNModulusBits //密钥长度 m_nShareBitLength //输入位长 maxShareBitLength 一个包的长度
	//uint32_t randomSeed = 2 * m_nShareBitLength + 41;
	std::ofstream send_out;
	
	send_out.open("ceshi.txt", std::ios::out | std::ios::app);
	
	

	//密钥需要的pack长度
	uint32_t packshares = numMTs * 5;
	//m_nDJNModulusBits / maxShareBitLength; // number of shares in one packet
	//(( ((numMTs) + (packshares)-1)/(packshares)))  
	uint32_t shareBytes = m_nShareBitLength / 8;
	uint32_t maxPackSharehNumber = 65536 / shareBytes;
	uint32_t numpacks = shareBytes * numMTs / 65536 + 1; // total number of packets to send in order to generate numMTs
	uint32_t limit = maxPackSharehNumber;
	uint32_t offset = 0;
	//uint32_t limit = maxPackSharehNumber; // upper bound for a package shares, used to handle non-full last packages / alignment

	uint64_t randomMax = pow(2, m_nShareBitLength);

	std::default_random_engine random(time(NULL));
    std::uniform_int_distribution<int> rand(0, randomMax - 1);


	//std::cout << "DJNModulusBits: " << m_nDJNModulusBits << " ShareBitLength: " << m_nShareBitLength << " packlen: " << maxPackSharehNumber << " numshares: " << packshares << " numpacks: " << numpacks << std::endl;


	mpz_t r, x, y, z, w, rr, u, v, mod;
	mpz_inits(r, x, y, z, w, rr, u, v, mod, NULL);

	
	// shares for client part
	mpz_t c[packshares];

	mpz_t a1[packshares];
	mpz_t b1[packshares];
	mpz_t c1[packshares];

	mpz_t X[packshares];
	mpz_t R[packshares];
	mpz_t Z[packshares];
	mpz_t W[packshares];
	mpz_t Y[packshares];
	mpz_t U[packshares];
	mpz_t V[packshares];

	for (uint32_t i = 0; i < packshares; i++) {
		mpz_inits(c[i], a1[i], b1[i], c1[i], U[i], V[i], X[i], Y[i], R[i], Z[i], W[i], NULL);
	}

	//allocate buffers for mpz_t ciphertext #numMTs with m_nBuflen
	//m_nBuflen = m_nDJNModulusBits / 8 + 1 加密后数据大小 Bytes
	BYTE * rbuf = (BYTE*) calloc(packshares * shareBytes, 1);
	BYTE * wbuf = (BYTE*) calloc(packshares * shareBytes, 1);

	BYTE * rbuf1 = (BYTE*) calloc(packshares * shareBytes, 1);
	BYTE * wbuf1 = (BYTE*) calloc(packshares * shareBytes, 1);

	BYTE * ubuf = (BYTE*) calloc(numMTs * shareBytes, 1);
	BYTE * vbuf = (BYTE*) calloc(numMTs * shareBytes, 1);

	BYTE * ubuf1 = (BYTE*) calloc(numMTs * shareBytes, 1);
	BYTE * vbuf1 = (BYTE*) calloc(numMTs * shareBytes, 1);

	clock_gettime(CLOCK_MONOTONIC, &start);

	mpz_t x1, x2, x3, x4, x5;
	mpz_inits(x1, x2, x3, x4, x5, NULL);

	mpz_t y1, y2, y3, y4, y5;
	mpz_inits(y1, y2, y3, y4, y5, NULL);


	// read server a,b shares and encrypt them into buffer
	//初始话向量X 每5个值为一组
	for (uint32_t i = 0; i < numMTs; i++) {
		mpz_import(x, 1, 1, shareBytes, 0, 0, bA + i * shareBytes);
		mpz_import(y, 1, 1, shareBytes, 0, 0, bB + i * shareBytes);
		
		//取值初始化向量（1，b0，a0，a0b0,-1）
		mpz_set_ui(x1, 1);

		mpz_set(x2, y);

		mpz_set(x3, x);

		mpz_mul(x4, x, y);
		mpz_mod_2exp(x4, x4, m_nShareBitLength);

		mpz_set_ui(x5, -1);
		mpz_mod_2exp(x5, x5, m_nShareBitLength);

		mpz_set(X[i*5], x1);
		mpz_set(X[i*5+1], x2);
		mpz_set(X[i*5+2], x3);
		mpz_set(X[i*5+3], x4);
		mpz_set(X[i*5+4], x5);

		//std::cout << "A  " << x << "B: " << y  << std::endl;
		//send_out << "A  " << x << "B: " << y  << std::endl;
		//std::cout << "x1  " << x1 << "x2: " << x2 << "x3  " << x3 << "x4: " << x4 << "x5: " << x5 << std::endl;
		//std::cout << "x1  " << X[i*4] << "x2: " << X[i*4+1] << "x3  " << X[i*4+2] << "x4: " << X[i*4+3]  << std::endl;

	}

	//随机数r
	
	//mpz_mod_2exp(rr, r, m_nShareBitLength);
	//gmp_printf("%Zd\n",rr);

	//初始化向量R 是一组随机数 加入缓存区
	//初始话向量Z z = x - r
	for(uint32_t i = 0; i < packshares; i++) {
		
		mpz_set_ui (r, rand(random));
		mpz_set(R[i], r);
		mpz_sub(z, X[i], R[i]);
		mpz_mod_2exp(z, z, m_nShareBitLength);
		mpz_set(Z[i], z);
		//std::cout << "rr  " << rr << "Z: " << z  << std::endl;
		//std::cout << "rr  " << R[i] << "Z: " << Z[i]  << std::endl;
		//send_out  << "rr  " << R[i] << "Z: " << Z[i]  << std::endl;
		
		mpz_export(rbuf + i * shareBytes, NULL, -1, 1, 1, 0, r);

	}


	mpz_set_ui(rr, 11);

	//初始化向量W 加入缓存区
	//w = rr * z
	for(uint32_t i = 0; i < packshares; i++) {
		
		mpz_mul(w, rr, Z[i]);
		mpz_mod_2exp(w, w, m_nShareBitLength);
		mpz_set(W[i], w);
		//std::cout << "rr  " << rr << "W: " << w  << std::endl;
		//send_out  << "rr  " << rr << "W: " << w  << std::endl;
		//std::cout << "rr  " << rr << "w: " << Z[i]  << std::endl;
	
		mpz_export(wbuf + i * shareBytes, NULL, -1, 1, 1, 0, w);

	}
	//for(uint32_t i = 0; i < packshares; i++) {
		
		
		//std::cout << "rr  " << rr << "W: " << w  << std::endl;
		//std::cout << "fasong rr  " << R[i] << "fasong w: " << W[i]  << std::endl;
	
	

	//}

	//初始化向量Y(a1b1,a1b1,1,c1)，初始化c1
	//原c1没有赋值 ，得重新写一组随机值进去
	offset = 0;
	for(uint32_t i = 0; i < numMTs; i++) {
		//取值初始化向量Y（a1b1，a1，b1，1,c1）
		mpz_import(a1[i], 1, 1, shareBytes, 0, 0, bA1 + offset);
		mpz_import(b1[i], 1, 1, shareBytes, 0, 0, bB1 + offset);

		mpz_set_ui (z, rand(random));

		mpz_set(c1[i], z);  

		mpz_export(bC1 + offset, NULL, 1, shareBytes, 0, 0, c1[i]);

		mpz_mul(y1, a1[i], b1[i]);
		mpz_mod_2exp(y1, y1, m_nShareBitLength);

		mpz_set(y2, a1[i]);

		mpz_set(y3, b1[i]);

		mpz_set_ui(y4, 1);
		mpz_mod_2exp(y4, y4, m_nShareBitLength);

		mpz_set(y5, z);

		mpz_set(Y[i*5], y1);
		mpz_set(Y[i*5+1], y2);
		mpz_set(Y[i*5+2], y3);
		mpz_set(Y[i*5+3], y4);
		mpz_set(Y[i*5+4], y5);

		//std::cout << "A1  " << a1[i] << "B1: " << b1[i] << "C1: " << z  << std::endl;
		//send_out  << "A1  " << a1[i] << "B1: " << b1[i] << "C1: " << z  << std::endl;
		//std::cout << "A1  " << a1[i] << "B1: " << b1[i] << "C1: " << c1[i]  << std::endl;
		//std::cout << "y1  " << y1 << "y2: " << y2 << "y3  " << y3 << "y4: " << y4  << "y5: " << y5 << std::endl;
		//std::cout << "y1  " << Y[i*4] << "y2: " << Y[i*4+1] << "y3  " << Y[i*4+2] << "y4: " << Y[i*4+3]  << std::endl;

		offset += shareBytes;
	}

	//	m_nBuflen 为加密后数据大小 
	//	offset初始化为0
	// send & receive encrypted values
	int window = DJN_WINDOWSIZE;
	int tosend = shareBytes * packshares;
	offset = 0;

	while (tosend > 0) {

		window = std::min(window, tosend);

		chan->send(rbuf + offset, window);
		chan->blocking_receive(rbuf1 + offset, window);

		chan->send(wbuf + offset, window);
		chan->blocking_receive(wbuf1 + offset, window);

		tosend -= window;
		offset += window;
	}




	// ----------------#############   ###############-----------------------
	// pack ALL the packets



	offset = 0;
	for (uint32_t i = 0; i < numpacks; i++) {

		//最后一包的大小
		if (i == numpacks - 1) {
			limit = packshares %  maxPackSharehNumber ; // if last package, only fill buffers to requested size and discard remaining shares
		
		}
		//std::cout << "asdasd" << limit << std::endl;
		//read shares from client byte arrays
		for (uint32_t j = 0; j < limit; j++) {
			//std::cout << "limit  " << limit << std ::endl;
			
			mpz_import(r, shareBytes, -1, 1, 1, 0, rbuf1 + (j + i * maxPackSharehNumber) * shareBytes);
			mpz_import(w, shareBytes, -1, 1, 1, 0, wbuf1 + (j + i * maxPackSharehNumber) * shareBytes);
			//send_out  << "jieshou r  " << r << "jiehsou w: " << w  << std::endl;
			//std::cout << "jieshou r  " << r << "jiehsou w: " << w  << std::endl;
			//gmp_printf("%Zd\n", r);
			//gmp_printf("%Zd\n",	w);
			//std::cout <<"ver" <<std::endl;
			
			mpz_mul(u, Y[j + i * maxPackSharehNumber], r);
			mpz_mul(v, Y[j + i * maxPackSharehNumber], w);

			mpz_mod_2exp(u, u, m_nShareBitLength);
			mpz_mod_2exp(v, v, m_nShareBitLength);

			//gmp_printf("%Zd\n", u);
			//gmp_printf("%Zd\n",	v);
			//std::cout <<"ver" <<std::endl;

			mpz_set(U[j + i * maxPackSharehNumber], u);
			mpz_set(V[j + i * maxPackSharehNumber], v);
			//gmp_printf("%Zd\n", U[j + i * maxSharehNumber]);
			//gmp_printf("%Zd\n",	V[j + i * maxSharehNumber]);
			//std::cout <<"ver" <<std::endl;

			//std::cout << "r  " << r << "w: " << w  << std::endl;
			//std::cout << "u  " << u << "v: " << v  << std::endl;
			//std::cout << "u  " << U[j + i * maxPackSharehNumber] << "v: " << V[j + i * maxPackSharehNumber]  << std::endl;
			
			offset += shareBytes;
		}

	}


	// ----------------#############   ###############-----------------------
	// all packets packed. exchange these packets
	//mpz_set(u, U[0]);
	//mpz_set(v, V[0]);

	for(uint32_t i = 0; i < packshares; i = i + 5) {
		
		mpz_set(u, U[i]);
		mpz_add(u, u, U[i+1]);
		mpz_add(u, u, U[i+2]);
		mpz_add(u, u, U[i+3]);
		mpz_add(u, u, U[i+4]);
		mpz_mod_2exp(u, u, m_nShareBitLength);

		mpz_export(ubuf + i / 5 * shareBytes, NULL, -1, 1, 1, 0, u);

		mpz_set(v, V[i]);
		mpz_add(v, v, V[i+1]);
		mpz_add(v, v, V[i+2]);
		mpz_add(v, v, V[i+3]);
		mpz_add(v, v, V[i+4]);
		mpz_mod_2exp(v, v, m_nShareBitLength);

		mpz_export(vbuf + i / 5 * shareBytes, NULL, -1, 1, 1, 0, v);

		
		std::cout << "fasong u  " << u << "fasong v: " << v  << std::endl;
		//send_out  << "fasong u  " << u << "fasong v: " << v  << std::endl;

	}

	window = DJN_WINDOWSIZE;
	tosend = shareBytes * numMTs;
	offset = 0;

	while (tosend > 0) {
		window = std::min(window, tosend);

		chan->send(ubuf + offset, window);
		chan->blocking_receive(ubuf1 + offset, window);
		
		chan->send(vbuf + offset, window);
		chan->blocking_receive(vbuf1 + offset, window);

		tosend -= window;
		offset += window;
	}

	//mpz_sub_ui(rr, rr, 1);
	//mpz_mod_2exp(rr, rr, m_nShareBitLength);

	offset = 0;
	limit = maxPackSharehNumber;
	for (uint32_t i = 0; i < numpacks; i++) {
		//最后一包的大小
		if (i == numpacks - 1) {
			limit = numMTs %  maxPackSharehNumber ; // if last package, only fill buffers to requested size and discard remaining shares
		}
		
		//read shares from client byte arrays
		for (uint32_t j = 0; j < limit; j++) {

			mpz_import(u, shareBytes, -1, 1, 1, 0, ubuf1 + (j + i * maxPackSharehNumber) * shareBytes);
			mpz_import(v, shareBytes, -1, 1, 1, 0, vbuf1 + (j + i * maxPackSharehNumber) * shareBytes);

			//std::cout << "jieshou u: " << u << "jieshou v: " << v << std::endl;

			//mpz_powm (mpz_t rop, mpz_t base, mpz_t exp, mpz_t mod) 

			//mpz_set_ui(mod, randomMax);

			//mpz_powm_ui(rr,  rr, -1,  mod);

			mpz_set_ui(rr, 163);
			mpz_mul(c[j + i * maxPackSharehNumber], rr, v);

			mpz_add(c[j + i * maxPackSharehNumber], c[j + i * maxPackSharehNumber], u);

			mpz_mod_2exp(c[j + i * maxPackSharehNumber], c[j + i * maxPackSharehNumber], m_nShareBitLength);

			std::cout << "u: " << u << "v: " << v << " rr: " << rr << " c  " << c[j + i * maxPackSharehNumber] << std::endl;
			//send_out  << "u: " << u << "v: " << v << " rr: " << rr << " c  " << c[j + i * maxPackSharehNumber] << std::endl;

			mpz_export(bC + offset, NULL, 1, shareBytes, 0, 0, c[j + i * maxPackSharehNumber]);
			offset += shareBytes;
			
		}

	}

	send_out.close();

	mpz_t ai, bi, ci, ai1, bi1, ci1, ta, tb;
	mpz_inits(ai, bi, ci, ai1, bi1, ci1, ta, tb, NULL);

	chan->send(bA, numMTs * shareBytes);
	chan->blocking_receive(bA, numMTs * shareBytes);
	chan->send(bB, numMTs * shareBytes);
	chan->blocking_receive(bB, numMTs * shareBytes);
	chan->send(bC, numMTs * shareBytes);
	chan->blocking_receive(bC, numMTs * shareBytes);

	for (uint32_t i = 0; i < numMTs; i++) {

		mpz_import(ai, 1, 1, shareBytes, 0, 0, bA + i * shareBytes);
		mpz_import(bi, 1, 1, shareBytes, 0, 0, bB + i * shareBytes);
		mpz_import(ci, 1, 1, shareBytes, 0, 0, bC + i * shareBytes);

		mpz_import(ai1, 1, 1, shareBytes, 0, 0, bA1 + i * shareBytes);
		mpz_import(bi1, 1, 1, shareBytes, 0, 0, bB1 + i * shareBytes);
		mpz_import(ci1, 1, 1, shareBytes, 0, 0, bC1 + i * shareBytes);

		mpz_add(ta, ai, ai1);
		mpz_add(tb, bi, bi1);
		mpz_mul(ta, ta, tb);
		mpz_add(tb, ci, ci1);
		mpz_mod_2exp(ta, ta, m_nShareBitLength);
		mpz_mod_2exp(tb, tb, m_nShareBitLength);

		if (mpz_cmp(ta, tb) == 0) {
			std::cout << "MT is fine - i:" << i << "| " << ai << " " << bi << " " << ci << " . " << ai1 << " " << bi1 << " " << ci1 << std::endl;
		} else {
			std::cout << "Error in MT - i:" << i << "| " << ai << " " << bi << " " << ci << " . " << ai1 << " " << bi1 << " " << ci1 << std::endl;
		}

		//std::cout << (mpz_cmp(c1[i], a1[i]) == 0 ? "MT is fine." : "Error in MT!") << std::endl;
	}
	mpz_clears(ai, bi, ci, ai1, bi1, ci1, ta, tb, NULL);


	clock_gettime(CLOCK_MONOTONIC, &end);

#if DJN_BENCH
	printf("generating 2x %u MTs took %f\n", numMTs, getMillies(start, end));
#endif

//clean up after ourselves
	for (uint32_t i = 0; i < packshares; i++) {
		mpz_clears(c[i], a1[i], b1[i], c1[i], U[i], V[i], X[i], Y[i], R[i], Z[i], W[i], NULL);
	}

	mpz_clears(r, x, y, z, w, rr, u, v, NULL);

	free(rbuf);
	free(wbuf);
	free(ubuf);
	free(vbuf);
}


/**
 * Interleaved sending and receiving. Server and client role at the same time for load balancing.
 * a,b,c are server shares. a1,b1,c1 are client shares.
 * All mpz_t values must be pre-initialized.
 */
void DJNParty::benchPreCompPacking1(channel* chan, BYTE * buf, uint32_t packlen, uint32_t numshares, mpz_t * a, mpz_t * b, mpz_t * a1, mpz_t * b1, mpz_t * c1, mpz_t r, mpz_t x,
		mpz_t y, mpz_t z) {
#if DJN_DEBUG
	std::cout << "packlen: " << packlen << " numshares: " << numshares << std::endl;
#endif

	for (uint32_t i = 0; i < numshares; i++) {
		djn_encrypt_crt(r, m_localpub, m_prv, a[i]);
		mpz_export(buf + 2 * i * m_nBuflen, NULL, -1, 1, 1, 0, r);
		djn_encrypt_crt(r, m_localpub, m_prv, b[i]);
		mpz_export(buf + (2 * i + 1) * m_nBuflen, NULL, -1, 1, 1, 0, r);
	}

	chan->send(buf, (uint64_t) m_nBuflen * numshares * 2);

#if DJN_NETDEBUG
	std::cout << " SEND " << std::endl;
	for (uint32_t xx=0; xx < m_nBuflen * numshares * 2; xx++) {
		printf("%02x.", *(buf + xx));
	}
#endif

	chan->blocking_receive(buf, (uint64_t) m_nBuflen * numshares * 2);

#if DJN_NETDEBUG
	std::cout << " RECV " << std::endl;
	for (uint32_t xx=0; xx < m_nBuflen * numshares * 2; xx++) {
		printf("%02x.", *(buf + xx));
	}
#endif

	for (uint32_t i = 0; i < numshares; i++) {
		mpz_import(x, m_nBuflen, -1, 1, 1, 0, buf + 2 * i * m_nBuflen);
		mpz_import(y, m_nBuflen, -1, 1, 1, 0, buf + (2 * i + 1) * m_nBuflen);

		dbpowmod(c1[i], x, b1[i], y, a1[i], m_remotepub->n_squared); //double base exponentiation
	}

// horner packing of shares into 1 ciphertext
	mpz_set(z, c1[numshares - 1]);
	mpz_set_ui(y, 0);
	mpz_setbit(y, packlen); // y = 2^ShareBitLength, for shifting ciphertext

	for (int i = numshares - 2; i >= 0; i--) {
		mpz_powm(z, z, y, m_remotepub->n_squared);
		mpz_mul(z, z, c1[i]);
		mpz_mod(z, z, m_remotepub->n_squared);
	}

// pick random r for masking
	aby_prng(x, mpz_sizeinbase(m_remotepub->n, 2) + 128);
	mpz_mod(x, x, m_remotepub->n);
	djn_encrypt_fb(y, m_remotepub, x);

// "add" encrypted r and send
	mpz_mul(z, z, y);
	mpz_mod(z, z, m_remotepub->n_squared);

// calculate c shares for client part
	for (uint32_t i = 0; i < numshares; i++) {
		mpz_mod_2exp(y, x, m_nShareBitLength); // y = r mod 2^ShareBitLength == read the share from least significant bits
		mpz_div_2exp(x, x, packlen); // r = r >> packlen

		mpz_mul(c1[i], a1[i], b1[i]); //c = a * b
		mpz_sub(c1[i], c1[i], y); // c = c - y

		mpz_mod_2exp(c1[i], c1[i], m_nShareBitLength); // c = c mod 2^ShareBitLength
	}
}

/**
 * exchanges private keys with other party via sock, pre-calculates fixed-base representation of remote pub-key
 */
void DJNParty::keyExchange(channel* chan) {

//send public key
	sendmpz_t(m_localpub->n, chan);
	sendmpz_t(m_localpub->h, chan);

//receive and complete public key
	mpz_t a, b;
	mpz_inits(a, b, NULL);
	receivempz_t(a, chan); //n
	receivempz_t(b, chan); //h
	djn_complete_pubkey(m_nDJNModulusBits, &m_remotepub, a, b);

// pre calculate table for fixed-base exponentiation for client
	fbpowmod_init_g(m_remotepub->h_s, m_remotepub->n_squared, 2 * m_nDJNModulusBits);

//free a and b
	mpz_clears(a, b, NULL);

#if DJN_DEBUG
	std::cout << "KX done. This pubkey: " << m_localpub->n << " remotekey: " << m_remotepub->n << std::endl;
#endif
}

/**
 * send one mpz_t to sock
 */
void DJNParty::sendmpz_t(mpz_t t, channel* chan, BYTE * buf) {

//clear upper bytes of the buffer, so tailing bytes are zero
	for (uint32_t i = mpz_sizeinbase(t, 256); i < m_nBuflen; i++) {
		*(buf + i) = 0;
	}

#if DJN_NETDEBUG2
	std::cout << mpz_sizeinbase(t, 256) << " vs. " << m_nBuflen << std::endl;
#endif

	mpz_export(buf, NULL, -1, 1, 1, 0, t);

	//send Bytes of t
	chan->send(buf, (uint64_t) m_nBuflen);

#if DJN_NETDEBUG
	std::cout << std::endl << "SEND" << std::endl;
	for (uint32_t i = 0; i < m_nBuflen; i++) {
		printf("%02x.", *(m_sendbuf + i));
	}

	std::cout << std::endl << "sent: " << t << " with len: " << m_nBuflen << " should have been " << mpz_sizeinbase(t, 256) << std::endl;
#endif
}

/**
 * receive one mpz_t from sock. t must be initialized.
 */
void DJNParty::receivempz_t(mpz_t t, channel* chan, BYTE * buf) {
	chan->blocking_receive(buf, (uint64_t) m_nBuflen);
	mpz_import(t, m_nBuflen, -1, 1, 1, 0, buf);

#if DJN_NETDEBUG
	std::cout << std::endl << "RECEIVE" << std::endl;
	for (uint32_t i = 0; i < m_nBuflen; i++) {
		printf("%02x.", *(m_recbuf + i));
	}

	std::cout << "received: " << t << " with len: " << m_nBuflen << std::endl;
#endif
}

/**
 * send one mpz_t to sock, allocates buffer
 */
void DJNParty::sendmpz_t(mpz_t t, channel* chan) {
	unsigned int bytelen = mpz_sizeinbase(t, 256);
	BYTE* arr = (BYTE*) malloc(bytelen);
	mpz_export(arr, NULL, 1, 1, 1, 0, t);

//send byte length
	chan->send((BYTE*) &bytelen, sizeof(bytelen));

//send bytes of t
	chan->send(arr, (uint64_t) bytelen);

	free(arr);
#if DJN_NETDEBUG
	std::cout << "sent: " << t << " with len: " << bytelen << std::endl;
#endif
}

/**
 * receive one mpz_t from sock. t must be initialized.
 */
void DJNParty::receivempz_t(mpz_t t, channel* chan) {
	unsigned int bytelen;

//reiceive byte length
	chan->blocking_receive((BYTE*) &bytelen, sizeof(bytelen));
	BYTE* arr = (BYTE*) malloc(bytelen);

//receive bytes of t
	chan->blocking_receive(arr, (uint64_t) bytelen);
	mpz_import(t, bytelen, 1, 1, 1, 0, arr);

	free(arr);
#if DJN_NETDEBUG
	std::cout << "received: " << t << " with len: " << bytelen << std::endl;
#endif
}

#if DJN_DEBUG
void DJNParty::printBuf(BYTE* b, uint32_t len) {
	for (uint32_t i = 0; i < len; i++) {
		printf("%02x.", *(b + i));
	}
	std::cout << std::endl;
}
#endif
