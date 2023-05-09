// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

using ECDSA for bytes32;

struct sigUnit {
    uint[] idx;
    bytes pk;
    bytes32[] proof;
    bytes32 root;
    bytes32 sigR;
    bytes32 sigVS;
}

contract SafeSign{
    uint constant n = 10;
    uint constant mu = 16;
    uint constant m = 8;
    bytes constant pp = 'ECDSA-SECP256K1';

    function pkToAddress(bytes memory pk) public pure returns (address) {
        return address(uint160(uint256(keccak256(pk))));
    }

    function randomChoice(bytes32 seed) public pure returns (uint[mu] memory) {
        uint[mu] memory choice;
        uint iter = 0;
        bytes32 out = 0x0;
        uint cnt = 0;
        while (cnt < mu) {
            out = keccak256(abi.encodePacked(seed, Strings.toString(iter), out));
            iter++;
            uint256 randInts = uint256(out);
            while (randInts >= (1 << n) && cnt < mu) {
                uint c = randInts & ((1 << n) - 1);
                randInts = randInts >> n;
                bool duplicate = false;
                for (uint i = 0; i < cnt; i++) {
                    if (c == choice[i]) {
                        duplicate = true;
                        break;
                    }
                }
                if (!duplicate) {
                    choice[cnt] = c;
                    cnt++;
                }
            }
        }
        return choice;
    }

    function _verifyECDSAsig(bytes memory data, bytes32 r, bytes32 vs, address account) public pure returns (bool) {
        return keccak256(data).recover(r, vs) == account;
    }

    function _verifyECDSAmerkle(bytes32[] memory proof, bytes32 root, bytes memory leaf) public pure returns (bool) {
        return MerkleProof.verify(proof, root, keccak256(leaf));
    }

    function _verifySafeSign(bytes memory message, sigUnit[m] memory safeSignSig, bytes32 pk) public pure returns (bool) {
        bytes32 kMain = sha256(abi.encodePacked(pp, pk, message));
        bytes32 kPRG = sha256(abi.encodePacked(kMain, 'PRG'));
        bytes32 kSIG = sha256(abi.encodePacked(kMain, 'SIG'));

        uint[mu] memory choice = randomChoice(kPRG);
        // implement in python

        bool b = true;
        for (uint i = 0; i < safeSignSig.length; i++) {
            sigUnit memory s = safeSignSig[i];
            b = b && (s.idx.length == m);
            for (uint j = 0; j < m; j++) {
                bool contain = false;
                for (uint k = 0; k < mu; j++)
                {
                    if (s.idx[j] == choice[k]) {
                        contain = true;
                        break;
                    }
                }
                b = b && contain;
            }
            b = b && MerkleProof.verify(s.proof, s.root, keccak256(s.pk));
            b = b && _verifyECDSAsig(abi.encodePacked(kSIG), s.sigR, s.sigVS, pkToAddress(s.pk));
            if (b == false) {
                break;
            }
        }
        return b;
    }
}