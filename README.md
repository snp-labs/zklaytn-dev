124[![Go Report Card](https://goreportcard.com/badge/github.com/klaytn/klaytn)](https://goreportcard.com/report/github.com/klaytn/klaytn)
[![CircleCI](https://circleci.com/gh/klaytn/klaytn/tree/dev.svg?style=svg)](https://circleci.com/gh/klaytn/klaytn/tree/dev)
[![codecov](https://codecov.io/gh/klaytn/klaytn/branch/dev/graph/badge.svg)](https://codecov.io/gh/klaytn/klaytn)
[![GoDoc](https://godoc.org/github.com/klaytn/klaytn?status.svg)](https://pkg.go.dev/github.com/klaytn/klaytn)

# Klaytn + Precompiled Contract(MiMC7, Poseidon)

Official golang implementation of the Klaytn protocol. Please visit [KlaytnDocs](https://docs.klaytn.com/) for more details on Klaytn design, node operation guides and application development resources.

## MiMC
MiMC7 is mapped to Opcode 0x13.  
Detail MiMC protocol : https://eprint.iacr.org/2016/492.pdf  
Detail MiMC7 protocol : https://iden3-docs.readthedocs.io/en/latest/_downloads/a04267077fb3fdbf2b608e014706e004/Ed-DSA.pdf  
MiMC7 algorithm :  
```
// global variables
const ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617
let rc = []
rc[0] = keccak256("mimc7_seed")
for i = 1 to i <= 91
  rc[i] = keccak256(rc[i - 1])

// type(inputs) == byte[][]
function MiMC7(inputs)
  
  if len(inputs) <= 1 then
    return mimc7round(inputs[0], inputs[0])
  
  else
    let output = input[0]
    
    for i = 1 to i < len(inputs) do
      output = mimc7round(output, input[i])
    return output
    
    endfor
  endif

// type(m) == type(key) == byte[]
function mimc7round(m, key)
  let c = (m + key)^7 mod ORDER // round 1
  for i = 2 to i < 92 do    // round 2 ~ 91
    c = (c + key + rc[i])^7 mod ORDER
  endfor
  let output = (c + key + m + key) mod ORDER
  return output
```
## Poseidon
Poseidon is mapped to Opcode 0x14.  
The Poseidon protocol referred to https://github.com/iden3/go-iden3-crypto/tree/master/poseidon  

## Require
Go-lang version >= v1.16  
Truffle version <= 5.1.25  <br/><br/>

## Reinstall package
Changed Go-lang version :  

 Downloads go-lang package in <https://go.dev/dl/>  then   
```
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf ./go1.*.*.****-****.tar.*
```


Changed Truffle version :  
```
npm uninstall -g truffle
npm install -g truffle@5.1.23 
```
## Building from Sources

Building the Klaytn node binaries as well as utility tools, such as `kcn`, `kpn`, `ken`, `kbn`, `kscn`, `kspn`, `ksen`, `kgen`, `homi` and `abigen` requires
both a Go (version 1.14.1 or later) and a C compiler. You can install them using
your favorite package manager.
Once the dependencies are installed, run

    make all (or make {kcn, kpn, ken, kbn, kscn, kspn, ksen, kgen, homi, abigen})

## How to use shell script(klaytn/klay)

How to use script(klaytn/klay)
```
Usage:
    klay <command> <value>
The commands are:
       setup value      Same as '$ cp build/bin/k*n corecell/*n/bin/k*n.value' (value is program version. ex: 1.0.2)
       init value       Delete all nodes & init nodes(value is program version)
       start            Start kcn,kpn,ken(CCN & EN)
       status           Show CCN, EN status
       stop             Stop all network
       attach value     Attach to value(value:cn,pn,en)
       log value        Show value's log(value:cn,pn,en)
       remvdata         remove chain data
```

## Run Local network 


```
cd klaytn
make all
echo "export PATH=\$PATH:`pwd`" >> ~/.profile
source ~/.profile
make all
klay setup 1.0.0
klay init 1.0.0
klay start
```
## Test with Klaytn IDE
1. go to https://ide.klaytn.com/
2. click third button(Deploy & run transactions)

![image](https://user-images.githubusercontent.com/54879931/167826231-f7ac9298-2a39-4153-bef0-b5cb0f51b9c9.png)

3. set the environment to Web3 Provider & click OK button

<img src="https://user-images.githubusercontent.com/54879931/167827526-a3988313-8d5d-4d17-b6d8-3c1ef275a760.png" width="300" height="300"/>

## Test with truffle

```
cd truffletest
truffle deploy --network klaytn --reset
truffle --network klaytn console
```
In truffle console(call hashfunction and show logs)
```
let pre = await Precompiled.deployed()
pre.callmimc(["0x0000000000000000000000000000000000000000000000000000000000000000"])
pre.callposeidon(["0x0000000000000000000000000000000000000000000000000000000000000001"])
await pre.getPastEvents("showbytes32",{ fromBlock:0, toBlock:'latest'})
```

## How to Use PreCompiled Contract MiMC7 in Solidity
The input data must padded the remaining left side of 32bytes to "0". (ex 0x01 -> 0x0000000000000000000000000000000000000000000000000000000000000001)  
If solidity version order than v0.5.0, use "gas" instead of "gas()" as the first factor in the call function.

```
pragma solidity >=0.5.0
function callmimc(bytes32[] memory data) public returns (bytes32 result) {
  uint256 len = data.length*32;
  assembly {
    let memPtr := mload(0x40)
      let success := call(gas(), 0x13, 0, add(data, 0x20), len, memPtr, 0x20)
      //solc -v < 0.5.0    let success := call(gas, 0x13, 0, add(data, 0x20), len, memPtr, 0x20)
      switch success
      case 0 {
        revert(0,0)
      } default {
        result := mload(memPtr)
      }
  }
}
```

## How to Use PreCompiled Contract Poseidon in Solidity
The input data must padded the remaining left side of 32bytes to "0". (ex 0x01 -> 0x0000000000000000000000000000000000000000000000000000000000000001)  
If solidity version order than v0.5.0, use "gas" instead of "gas()" as the first factor in the call function.
```
pragma solidity >=0.5.0
function callposeidon(bytes32[] memory data) public returns (bytes32 result) {
  uint256 len = data.length*32;
  assembly {
    let memPtr := mload(0x40)
      let success := call(gas(), 0x14, 0, add(data, 0x20), len, memPtr, 0x20)
      //let success := call(gas, 0x14, 0, add(data, 0x20), len, memPtr, 0x20)
      switch success
      case 0 {
        revert(0,0)
      } default {
        result := mload(memPtr)
      }
  }
}
```

## How to Use PreCompiled Contract BLS in Solidity
```
contract Bls {
    event showbytes32(bytes32 output);
    event showbytes32arr(bytes32[] output);

    // General Bls12-381 format
    // each elements are 48 bytes
    // g1Affine :  96 bytes  (2 elements) -> g1.x, g1.y
    // g2Affine : 192 bytes  (4 elements) -> g2.x0, g2.x1, g2.y0, g2.y1
    //       gt : 576 bytes (12 elements) -> gt.c0, gt.c1 ... gt.c11

    // Go-eth Bls12-381 format
    // g1,g2's each elements are 64 bytes -> append 16 bytes of 0 to the front
    // g1 : 128 bytes -> [  concat([0u8;16], g1.x[:16]), g1.x[16:48], concat([0u8;16], g1.y[:16]), g1.y[16:48]  ]
    // g2 : 256 bytes -> in the same way as g1
    // gt : 576 bytes -> [ gt.c0[:32], concat(gt.c0[32:], gt.c1[:16]), gt.c1[16:], .... ]

    function ParingCmp(bytes32[] memory inputs) public returns (bytes32 result){
        // result = (e(a,A) + e(b,B) + e(c,C)... == gt)

        // inputs index      elements
        //  0 ~ 12*k-1     [(g1,  g2)]      // k : num of g1,g2 pair
        //  12*k ~              gt
        assembly{
            let len := mload(inputs)
            let memPtr := mload(0x40)
            let success := call(gas(), 0x17, 0, add(inputs, 0x20), mul(len, 0x20), memPtr, 0x20)
            switch success case 0 {
                revert(0, 0)
            }
            default {
                result := mload(memPtr)
            }
        }
        emit showbytes32(result);
    }

    function GtAdd(bytes32[] memory inputs) public returns (bytes32[] memory result){
        // result = (gt_1 + gt_2)

        // inputs index      elements
        //     0 ~ 17          gt_1
        //    18 ~             gt_2
        assembly{
            let len := mload(inputs)
            result := mload(0x40)
            mstore(result, 0x12)
            let success := call(gas(), 0x16, 0, add(inputs, 0x20), mul(len, 0x20), add(result, 0x20), mul(0x12, 0x20))
            switch success case 0 {
                revert(0, 0)
            }
            mstore(0x40, add(result, add(0x20, mul(0x12, 0x20))))
        }
        emit showbytes32arr(result);
    }

    function GtMul(bytes32[] memory inputs) public returns (bytes32[] memory result){
        // result = (gt^scaler)       // scaler : 32 bytes


        // inputs index      elements
        //    0 ~ 17            gt
        //   17 ~              scaler
        assembly{
            let len := mload(inputs)
            result := mload(0x40)
            mstore(result, 0x12)
            let success := call(gas(), 0x15, 0, add(inputs, 0x20), mul(len, 0x20), add(result, 0x20), mul(0x12, 0x20))
            switch success case 0 {
                revert(0, 0)
            }
            mstore(0x40, add(result, add(0x20, mul(0x12, 0x20))))
        }
        emit showbytes32arr(result);
    }
}

```