/* SPDX-FileCopyrightText: © 2020-2024 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: MIT */

package kyberk2so

import (
	"crypto/rand"

	"golang.org/x/crypto/sha3"
)

// Generates matrix in NTT, returns a and at
func GenerateMatrix(paramsK int) ([]polyvec, []polyvec, error) {
	buf := make([]byte, 2*paramsSymBytes)
	h := sha3.New512()
	_, err := rand.Read(buf[:paramsSymBytes])
	if err != nil {
		return nil, nil, err
	}
	_, err = h.Write(buf[:paramsSymBytes])
	if err != nil {
		return nil, nil, err
	}
	buf = buf[:0]
	buf = h.Sum(buf)
	publicSeed := make([]byte, paramsSymBytes)
	copy(publicSeed, buf[:paramsSymBytes])

	// Matrix generation part
	a, err := indcpaGenMatrix(publicSeed, false, paramsK)
	if err != nil {
		return nil, nil, err
	}

	at, err := indcpaGenMatrix(publicSeed, true, paramsK)
	if err != nil {
		return nil, nil, err
	}

	return a, at, nil
}

// Generates error in NTT
func GenerateError(paramsK int) (polyvec, error) {
	e := polyvecNew(paramsK)

	buf := make([]byte, 2*paramsSymBytes)
	h := sha3.New512()
	_, err := rand.Read(buf[:paramsSymBytes])
	if err != nil {
		return nil, err
	}
	_, err = h.Write(buf[:paramsSymBytes])
	if err != nil {
		return nil, err
	}
	buf = buf[:0]
	buf = h.Sum(buf)
	noiseSeed := make([]byte, paramsSymBytes)
	copy(noiseSeed, buf[paramsSymBytes:])

	var nonce byte
	for i := 0; i < paramsK; i++ {
		e[i] = polyGetNoise(noiseSeed, nonce, paramsK)
		nonce = nonce + 1
	}

	polyvecNtt(e, paramsK)
	return e, nil
}

// Generates private key in NTT
func GeneratePrivateKey(paramsK int) (polyvec, error) {
	skpv := polyvecNew(paramsK) // polyvec of length paramsK, [2]poly , poly = [384]int16

	buf := make([]byte, 2*paramsSymBytes)
	h := sha3.New512()
	_, err := rand.Read(buf[:paramsSymBytes])
	if err != nil {
		return nil, err
	}
	_, err = h.Write(buf[:paramsSymBytes])
	if err != nil {
		return nil, err
	}
	buf = buf[:0]
	buf = h.Sum(buf)

	noiseSeed := make([]byte, paramsSymBytes)

	copy(noiseSeed, buf[paramsSymBytes:])

	// Skpv and e generation part
	// Both of them have 2 elements of type poly (poly = [384]int16)
	// Values are between -3 and 3.. And only first 256 values are used
	var nonce byte
	for i := 0; i < paramsK; i++ {
		skpv[i] = polyGetNoise(noiseSeed, nonce, paramsK)
		nonce = nonce + 1
	}
	// Convert to NTT domain and reduce, prepared for multiplication
	polyvecNtt(skpv, paramsK)
	polyvecReduce(skpv, paramsK)

	return skpv, nil
}

// Generates public key
func GeneratePublicKey(a []polyvec, s polyvec, e polyvec, paramsK int) polyvec {
	pkpv := polyvecNew(paramsK)
	for i := 0; i < paramsK; i++ {
		pkpv[i] = polyToMont(polyvecPointWiseAccMontgomery(a[i], s, paramsK)) // A*s
	}

	polyvecAdd(pkpv, e, paramsK) // pkpv = A*s + e
	polyvecReduce(pkpv, paramsK)

	return pkpv
}

func CalculateSharedSecret(a polyvec, b polyvec, paramsK int) poly {
	/*
		Not sure this is needed, check kyber encryption as it's not using this
		doesn't changing result for now
		polyvecNtt(a, paramsK)
		polyvecReduce(a, paramsK)
	*/
	sp := polyToMont(polyvecPointWiseAccMontgomery(a, b, paramsK))

	return polyReduce(sp)
}
