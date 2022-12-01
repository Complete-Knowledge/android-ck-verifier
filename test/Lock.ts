import { time, loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import { expect } from "chai";
import { ethers } from "hardhat";

describe("X509Decoder", function () {
  // We define a fixture to reuse the same setup in every test.
  // We use loadFixture to run this setup once, snapshot that state,
  // and reset Hardhat Network to that snapshot in every test.
  async function deployContractsFixture() {
    // Contracts are deployed using the first signer/account by default
    const [owner, otherAccount] = await ethers.getSigners();

    const P256SHA256ContractFactory = await ethers.getContractFactory("P256SHA256Algorithm");
    const P256SHA256 = await P256SHA256ContractFactory.deploy();
    
    const DateTimeFactory = await ethers.getContractFactory("DateTime");
    const DateTime = await DateTimeFactory.deploy();
    
    const X509DecoderFactory = await ethers.getContractFactory("X509Parser");
    const xd = await X509DecoderFactory.deploy(P256SHA256.address, DateTime.address);

    return { xd };
  }

  describe("Deployment", function () {
    it("Should deploy contracts", async function () {
      const { xd } = await loadFixture(deployContractsFixture);
      expect(xd).to.not.equal(null);
    });
    
    it("Should parse a certificate", async function () {
      const { xd } = await loadFixture(deployContractsFixture);
      await xd.addCert(
            "0x308202d430820279a003020102020101300a06082a8648ce3d0403023039310c300a060355040a130354454531293027060355040313203664373032613963626339613439656562633964343036663862393462623338301e170d3730303130313030303030305a170d3438303130313030303030305a301f311d301b06035504031314416e64726f6964204b657973746f7265204b65793059301306072a8648ce3d020106082a8648ce3d0301070342000408bd9c214e28de869b5fb615fbcde9663f33e3c9ce40cd1de7479ee13df303970401b0395f0b9609d682007a453a94b38fceedd51231ff4b9f537d94a9a445f2a382018a30820186300e0603551d0f0101ff04040302078030820172060a2b06010401d679020111048201623082015e020200c80a0101020200c80a01010441c6d0f969e03173b708d8f49cd3aadb389ff82876c293c91b0e12c0fd9c9f383108360ac65f2cb63aa5c30b8290a22929f7c3e80693150335008333dcbaf7a8881b04003056bf853d0802060184cace6a65bf85454604443042311c301a0415636f6d2e6578616d706c652e616e64726f6964636b020101312204207322227e0a2a9bac891e1e3fda1fc16356b8e4a417c20c419627d28f3e083bf13081b0a1053103020102a203020103a30402020100a50b3109020104020105020106aa03020101bf837803020103bf8379040202012cbf853e03020100bf85404c304a04208b2c4cd539f5075e8e7cf212adb3db0413fbd77d321199c73d5a473c51f2e10d0101ff0a0100042092a169f2ac890d35022e76791565c123c56620dae3ffa41c4195e15a3f34390bbf854105020301fbd0bf85420502030315e1bf854e06020401348be9bf854f06020401348be9300a06082a8648ce3d0403020349003046022100a00d06e52b8c53a4d3b90cd21b271e7c98f4bad9cfe0acdb0f8df6dba54f8f27022100ab5b54e056afa1349effc598e0b52c5109071107e45e43cccdbf73d5870c704b",
      "0x0408bd9c214e28de869b5fb615fbcde9663f33e3c9ce40cd1de7479ee13df303970401b0395f0b9609d682007a453a94b38fceedd51231ff4b9f537d94a9a445f2"
      );
    });
  });
});
