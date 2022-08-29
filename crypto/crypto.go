// Modifications Copyright 2018 The klaytn Authors
// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.
//
// This file is derived from crypto/crypto.go (2018/06/04).
// Modified and improved for the klaytn development.

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"

	"github.com/klaytn/klaytn/common"
	"github.com/klaytn/klaytn/common/math"
	bn256 "github.com/klaytn/klaytn/crypto/bn256/google"
	"github.com/klaytn/klaytn/crypto/sha3"
	"github.com/klaytn/klaytn/rlp"
)

// SignatureLength indicates the byte length required to carry a signature with recovery id.
const SignatureLength = 64 + 1 // 64 bytes ECDSA signature + 1 byte recovery id

// RecoveryIDOffset points to the byte offset within the signature that contains the recovery id.
const RecoveryIDOffset = 64

// DigestLength sets the signature digest exact length
const DigestLength = 32

var (
	secp256k1N, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secp256k1halfN = new(big.Int).Div(secp256k1N, common.Big2)
)

var errInvalidPubkey = errors.New("invalid secp256k1 public key")

//MiMC7
var Mimc7Seed = Keccak256([]byte("mimc7_seed"))

//poseidon
var NROUNDSP = []int{56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68}

const NROUNDSF = 8

// Keccak256 calculates and returns the Keccak256 hash of the input data.
func Keccak256(data ...[]byte) []byte {
	d := sha3.NewKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

// Keccak256Hash calculates and returns the Keccak256 hash of the input data,
// converting it to an internal Hash data structure.
func Keccak256Hash(data ...[]byte) (h common.Hash) {
	d := sha3.NewKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	d.Sum(h[:0])
	return h
}

// Keccak512 calculates and returns the Keccak512 hash of the input data.
func Keccak512(data ...[]byte) []byte {
	d := sha3.NewKeccak512()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

// CreateAddress creates a Klaytn address given the bytes and the nonce
func CreateAddress(b common.Address, nonce uint64) common.Address {
	data, _ := rlp.EncodeToBytes(struct {
		Addr  common.Address
		Nonce uint64
	}{b, nonce})
	return common.BytesToAddress(Keccak256(data)[12:])
}

// CreateAddress2 creates a Klaytn address given the address bytes, initial
// contract code hash and a salt.
func CreateAddress2(b common.Address, salt [32]byte, inithash []byte) common.Address {
	return common.BytesToAddress(Keccak256([]byte{0xff}, b.Bytes(), salt[:], inithash)[12:])
}

// ToECDSA creates a private key with the given D value.
func ToECDSA(d []byte) (*ecdsa.PrivateKey, error) {
	return toECDSA(d, true)
}

// ToECDSAUnsafe blindly converts a binary blob to a private key. It should almost
// never be used unless you are sure the input is valid and want to avoid hitting
// errors due to bad origin encoding (0 prefixes cut off).
func ToECDSAUnsafe(d []byte) *ecdsa.PrivateKey {
	priv, _ := toECDSA(d, false)
	return priv
}

// toECDSA creates a private key with the given D value. The strict parameter
// controls whether the key's length should be enforced at the curve size or
// it can also accept legacy encodings (0 prefixes).
func toECDSA(d []byte, strict bool) (*ecdsa.PrivateKey, error) {
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = S256()
	if strict && 8*len(d) != priv.Params().BitSize {
		return nil, fmt.Errorf("invalid length, need %d bits", priv.Params().BitSize)
	}
	priv.D = new(big.Int).SetBytes(d)

	// The priv.D must < N
	if priv.D.Cmp(secp256k1N) >= 0 {
		return nil, fmt.Errorf("invalid private key, >=N")
	}
	// The priv.D must not be zero or negative.
	if priv.D.Sign() <= 0 {
		return nil, fmt.Errorf("invalid private key, zero or negative")
	}

	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(d)
	if priv.PublicKey.X == nil {
		return nil, errors.New("invalid private key")
	}
	return priv, nil
}

// FromECDSA exports a private key into a binary dump.
func FromECDSA(priv *ecdsa.PrivateKey) []byte {
	if priv == nil {
		return nil
	}
	return math.PaddedBigBytes(priv.D, priv.Params().BitSize/8)
}

// UnmarshalPubkey converts bytes to a secp256k1 public key.
func UnmarshalPubkey(pub []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(S256(), pub)
	if x == nil {
		return nil, errInvalidPubkey
	}
	return &ecdsa.PublicKey{Curve: S256(), X: x, Y: y}, nil
}

func FromECDSAPub(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return elliptic.Marshal(S256(), pub.X, pub.Y)
}

// HexToECDSA parses a secp256k1 private key.
func HexToECDSA(hexkey string) (*ecdsa.PrivateKey, error) {
	b, err := hex.DecodeString(hexkey)
	if err != nil {
		return nil, errors.New("invalid hex string")
	}
	return ToECDSA(b)
}

// LoadECDSA loads a secp256k1 private key from the given file.
func LoadECDSA(file string) (*ecdsa.PrivateKey, error) {
	buf := make([]byte, 64)
	fd, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	if _, err := io.ReadFull(fd, buf); err != nil {
		return nil, err
	}

	key, err := hex.DecodeString(string(buf))
	if err != nil {
		return nil, err
	}
	return ToECDSA(key)
}

// SaveECDSA saves a secp256k1 private key to the given file with
// restrictive permissions. The key data is saved hex-encoded.
func SaveECDSA(file string, key *ecdsa.PrivateKey) error {
	k := hex.EncodeToString(FromECDSA(key))
	return ioutil.WriteFile(file, []byte(k), 0o600)
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(S256(), rand.Reader)
}

// ValidateSignatureValues verifies whether the signature values are valid with
// the given chain rules. The v value is assumed to be either 0 or 1.
func ValidateSignatureValues(v byte, r, s *big.Int, homestead bool) bool {
	if r.Cmp(common.Big1) < 0 || s.Cmp(common.Big1) < 0 {
		return false
	}
	// reject upper range of s values (ECDSA malleability)
	// see discussion in secp256k1/libsecp256k1/include/secp256k1.h
	if homestead && s.Cmp(secp256k1halfN) > 0 {
		return false
	}
	// Frontier: allow s to be in full N range
	return r.Cmp(secp256k1N) < 0 && s.Cmp(secp256k1N) < 0 && (v == 0 || v == 1)
}

func PubkeyToAddress(p ecdsa.PublicKey) common.Address {
	pubBytes := FromECDSAPub(&p)
	return common.BytesToAddress(Keccak256(pubBytes[1:])[12:])
}

func zeroBytes(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
}

func Mimc7(data []byte) []byte {
	result := make([]byte, 32)
	no_padd := make([]byte, 32)
	m := new(big.Int).SetBytes(data[0:32])
	if len(data) <= 32 {
		no_padd = Mimc7round(m, m).Bytes()
	} else {
		for i := 32; i < len(data); i += 32 {
			key := new(big.Int).SetBytes(data[i : i+32])
			m = Mimc7round(m, key)
		}
		no_padd = m.Bytes()
	}
	copy(result[32-len(no_padd):], no_padd[:])
	return result
}

func Mimc7round(m *big.Int, key *big.Int) *big.Int {
	c := new(big.Int)
	ex := big.NewInt(7)
	c.Add(m, key).Exp(c, ex, bn256.Order)
	R_ := new(big.Int).SetBytes(Mimc7Seed)
	for i := 0; i < 90; i += 1 {
		R := Keccak256(R_.Bytes())
		R_ = new(big.Int).SetBytes(R)
		c.Add(c, key).Add(c, R_).Exp(c, ex, bn256.Order)
	}
	c.Add(c, key).Add(c, m).Add(c, key).Mod(c, bn256.Order)
	return c
}

func Poseidon(data []byte) []byte {
	result := make([]byte, 32)
	t := (len(data)-31)/32 + 1
	inputs := make([]*big.Int, t)
	j := 0
	for i := 0; i < len(data); i += 32 {
		inputs[j] = big.NewInt(0).SetBytes(data[i : i+32])
		j++
	}
	no_padd := Poseidon256(inputs).Bytes()
	copy(result[32-len(no_padd):], no_padd[:])
	return result
}

func Poseidon256(input []*big.Int) *big.Int {
	t := len(input) + 1
	nRoundsFDiv2 := NROUNDSF / 2
	nRoundsP := NROUNDSP[t-2]
	tmp := big.NewInt(0)
	tmp1 := big.NewInt(1)
	tmp2 := big.NewInt(3)
	tmp2.Add(tmp, tmp1)
	C := PoseidonConstant.c[t-2]
	S := PoseidonConstant.s[t-2]
	M := PoseidonConstant.m[t-2]
	P := PoseidonConstant.p[t-2]
	state := make([]*big.Int, t)
	state[0] = big.NewInt(0)
	for i := 0; i < t-1; i++ {
		state[i+1] = big.NewInt(0).Set(input[i])
	}
	ArrAdd(state, C, 0) //state = state + C[:]
	for i := 0; i < nRoundsFDiv2-1; i++ {
		ArrExp5(state)              // state = state^5
		ArrAdd(state, C, (i+1)*t)   // state = state[:] + C[(i+1)*t: ] -> loop len(state)
		state = VecMatMul(state, M) // state = state * M
	}
	ArrExp5(state)                     // state = state^5
	ArrAdd(state, C, (nRoundsFDiv2)*t) // state = ...state[:] + ...C[nRoundsF/2*t: ] -> loop len(state)
	state = VecMatMul(state, P)        // state = state * P ->  Vec=state;  Mat=P;
	for i := 0; i < nRoundsP; i++ {
		state[0].Exp(state[0], big.NewInt(5), bn256.Order) // state[0] = state[0]^5
		state[0].Add(state[0], C[(nRoundsFDiv2+1)*t+i])    // state[0] += C[(nRoundsF/2+1)*t + i]
		mul := big.NewInt(0)
		newState0 := big.NewInt(0)
		for j := 0; j < t; j++ {
			mul.Mul(S[(t*2-1)*i+j], state[j]) // mul = S[(t*2-1)*i+j] * state[j]
			newState0.Add(newState0, mul)     // newState0 += mul
		}
		for k := 1; k < t; k++ {
			mul.Mul(state[0], S[(t*2-1)*i+t+k-1]) // mul = state[0] * S[(t*2-1)*i+t+k-1]
			state[k].Add(state[k], mul)           // state[k] += mul
		}
		state[0] = newState0 //state[0] = newState0
	}
	for i := 0; i < nRoundsFDiv2-1; i++ {
		ArrExp5(state)                                  // state = [(...state)^5]
		ArrAdd(state, C, (nRoundsFDiv2+1+i)*t+nRoundsP) // state = state + C[(nRoundsF/2+1)*t+sP[t-2]+i*t:] -> loop len(state)
		state = VecMatMul(state, M)                     // state = state * M ->  Vec=state;  Mat=M;
	}
	ArrExp5(state)              // state = [(...state)^5]
	state = VecMatMul(state, M) // state = state * M ->  Vec=state;  Mat=M;
	return state[0]             // hash result = state[0]
}

func ArrExp(x []*big.Int, y *big.Int) {
	for i := 0; i < len(x); i++ {
		x[i].Exp(x[i], y, bn256.Order)
	}
}
func ArrExp5(x []*big.Int) {
	ArrExp(x, big.NewInt(5))
}

// addArray computes x = x[:] + y[mv:]
func ArrAdd(x []*big.Int, y []*big.Int, mv int) {
	for i := 0; i < len(x); i++ {
		x[i].Add(x[i], y[mv+i]) //.Mod(x[i], ff.Modulus())
	}
}
func VecMatMul(x []*big.Int, y [][]*big.Int) []*big.Int {
	l := len(x)
	result := make([]*big.Int, l)
	mul := new(big.Int)
	for i := 0; i < l; i++ {
		result[i] = big.NewInt(0)
		for j := 0; j < l; j++ {
			mul.Mul(y[j][i], x[j])
			result[i].Add(result[i], mul)
		}
		result[i].Mod(result[i], bn256.Order)
	}
	return result
}
