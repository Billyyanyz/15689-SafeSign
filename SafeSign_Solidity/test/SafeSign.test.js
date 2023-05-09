const {expect} = require("chai");
const {ethers} = require("hardhat");
const { isCallTrace } = require("hardhat/internal/hardhat-network/stack-traces/message-trace");

describe('SafeSign', function () {
    before(async function () {
        this.SafeSign = await ethers.getContractFactory('SafeSign');
    });

    beforeEach(async function () {
        this.safesign = await this.SafeSign.deploy();
        await this.safesign.deployed();
    });

    /*it('check signature', async function() {
        const addr = await this.safesign.pkToAddress(
            Buffer.from(
                "2300d758ff3942ff4cc733651c1f92ae3ad87a3880ced4ae3d36b5496324cf1d0ae8bcfa2364eb93748c37e4841c8e3a6c79c168acd9e20850b50b83cc92e035", "hex"
                )
        );
        expect((await this.safesign._verifyECDSAsig(
            Buffer.from("3ea2f1d0abf3fc66cf29eebb70cbd4e7fe762ef8a09bcc06c8edf641230afec0", "hex"),
            Buffer.from("bb125aa9d9400e7dcbce16e3829948f1315f10f80e91fcad17897e93800c9fcc", "hex"),
            Buffer.from("eafd2a35558409ab714be0363554f509dd5baaf562e511fb464d5d784f1c9a47", "hex"),
            addr
        )) == true)
    })*/

    /*it('check merkle tree', async function() {
        const proof = new Array(
            Buffer.from("0b887609932d9e36dd9b0efe308b639f1ec4ddcab4bad32e5fb42b2cc7e0e81c", "hex"),
            Buffer.from("313860ebc93f334a5b3dc50a529a3bd2b7c0fb020fd37ff4b6e5fcdff8563c42", "hex"),
            Buffer.from("46732ff99f1ef17c5c40fe5e16ac23ee541885c6bc7122408154e00ce5697145", "hex"),
            Buffer.from("9aaa42ec4e8c25414055e3d127c8d5570e580e9e7ea3dc9ae35027e3154924d5", "hex"),
        )
        expect((await this.safesign._verifyECDSAmerkle(
            proof,
            Buffer.from("e3d83a5c15dd7d2356cb3c9a617261501745b17f4f7ba13ac1b3285f144c1dbd", "hex"),
            Buffer.from(
                "2300d758ff3942ff4cc733651c1f92ae3ad87a3880ced4ae3d36b5496324cf1d0ae8bcfa2364eb93748c37e4841c8e3a6c79c168acd9e20850b50b83cc92e035", "hex"
                )

        )) == true)
    })*/

    it('check rng', async function() {
        const seed = Buffer.from("3ea2f1d0abf3fc66cf29eebb70cbd4e7fe762ef8a09bcc06c8edf641230afec0", "hex")
        const ret = new Array(730, 826, 137, 692, 988)
        expect((await this.safesign.randomChoice(seed)) == ret)
    })
})
