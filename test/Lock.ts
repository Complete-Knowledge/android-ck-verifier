import { time, loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import { expect } from "chai";
import { ethers } from "hardhat";
import { randomBytes } from "crypto";

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

    return { xd, P256SHA256 };
  }

  describe("Deployment", function () {
    it("Should deploy contracts", async function () {
      const { xd } = await loadFixture(deployContractsFixture);
      expect(xd).to.not.equal(null);
    });
    
    it("Should pass basic signature validation", async function() {
        const { P256SHA256 } = await loadFixture(deployContractsFixture);
        let res = await P256SHA256.verify(
            "0x00000000B7E08AFDFE94BAD3F1DC8C734798BA1C62B3A0AD1E9EA2A38201CD0889BC7A193603F747959DBF7A4BB226E41928729063ADC7AE43529E61B563BBC606CC5E09",
            "0x4578616d706c65206f66204543445341207769746820502d323536",
            "0x2B42F576D07F4165FF65D1F3B1500F81E44C316F1F0B3EF57325B69ACA46104FDC42C2122D6392CD3E3A993A89502A8198C1886FE69D262C4B329BDB6B63FAF1"
        );
        expect(res).to.be.true;
    });
    
    it("Should pass signature validation on a sample certificate payload", async function() {
        const { P256SHA256 } = await loadFixture(deployContractsFixture);
        console.log("Signature validation on sample payload:");
        let res = await P256SHA256.verify(
            "0x0000000060225dea1eb30c0b1ed9faa64c95f296262bf946b6a099cc630f6c4531cbe8cba1bbff136cec829bc5bf97101481fad8e9ced8e7fbc53e049886ae7fdc447a83",
            "0x30820279a003020102020101300a06082a8648ce3d0403023039310c300a060355040a130354454531293027060355040313203664373032613963626339613439656562633964343036663862393462623338301e170d3730303130313030303030305a170d3438303130313030303030305a301f311d301b06035504031314416e64726f6964204b657973746f7265204b65793059301306072a8648ce3d020106082a8648ce3d03010703420004b7984e4c240eaf334688533606c1624efe72fb186d276d7e3a556f95e8bbfa3e70e88210e100a50f6ab4fe1fc9abf3605884661bb7166b7f9fae2d99afa4e6f9a382018a30820186300e0603551d0f0101ff04040302078030820172060a2b06010401d679020111048201623082015e020200c80a0101020200c80a010104413963624277e3c87e9dd53f28bb4ccd53a1900e4d577d37fa7dc87d78a886720f647e1589b96fd9b62a4f6824703c08a153be7d64f9a5a2322dabf19e551da1181c04003056bf853d0802060184ca7463adbf85454604443042311c301a0415636f6d2e6578616d706c652e616e64726f6964636b020101312204207322227e0a2a9bac891e1e3fda1fc16356b8e4a417c20c419627d28f3e083bf13081b0a1053103020102a203020103a30402020100a50b3109020104020105020106aa03020101bf837803020103bf8379040202012cbf853e03020100bf85404c304a04208b2c4cd539f5075e8e7cf212adb3db0413fbd77d321199c73d5a473c51f2e10d0101ff0a0100042092a169f2ac890d35022e76791565c123c56620dae3ffa41c4195e15a3f34390bbf854105020301fbd0bf85420502030315e1bf854e06020401348be9bf854f06020401348be9",
            "0xcce8932d78853889f7b5d669e475dcb5098cd070d82cd208860944ab08a45ce49f3f5d31731ba87109b54b4953a6863dc35c5782fbd03871125676a93ce880d2"
        );
        expect(res).to.be.true;
    });
    
    it("Should parse a certificate", async function () {
      const { xd } = await loadFixture(deployContractsFixture);
      await expect(xd.addCert(
            "0x308202cc30820273a003020102020101300a06082a8648ce3d0403023039310c300a060355040a130354454531293027060355040313203664373032613963626339613439656562633964343036663862393462623338301e170d3730303130313030303030305a170d3438303130313030303030305a301f311d301b06035504031314416e64726f6964204b657973746f7265204b65793059301306072a8648ce3d020106082a8648ce3d03010703420004be434ab043ab09658cf178a6f19c9518835d90b8dfe10f836dd00f6aae9a68c251426f075ef85f93e71b5b953101269504e216c2a1f4c36be5d75d1211782f08a382018430820180300e0603551d0f0101ff0404030207803082016c060a2b06010401d6790201110482015c30820158020200c80a0101020200c80a01010441ba21a7851ddb5b251d5c3cbfcd7b58c60385de17ba815e3bffaa60f410ed4dd86ec7970393445d1d34748fed459851e5419d00198ec1dbaff2406f536c75c6061c04003056bf853d0802060184d46f3b74bf85454604443042311c301a0415636f6d2e6578616d706c652e616e64726f6964636b020101312204207322227e0a2a9bac891e1e3fda1fc16356b8e4a417c20c419627d28f3e083bf13081aaa1053103020102a203020103a30402020100a5053103020104aa03020101bf837803020103bf8379040202012cbf853e03020100bf85404c304a04208b2c4cd539f5075e8e7cf212adb3db0413fbd77d321199c73d5a473c51f2e10d0101ff0a0100042092a169f2ac890d35022e76791565c123c56620dae3ffa41c4195e15a3f34390bbf854105020301fbd0bf85420502030315e1bf854e06020401348be9bf854f06020401348be9300a06082a8648ce3d040302034700304402207e7fed041caa2c3b931b6ea550ca5e5234fe96396e93a5552e229005481e760602202254f0d432bafb6507c68733ebefcc15b6b247dfa3ddfdc233dc33077bb1d749",
      ["0x0000000060225dea1eb30c0b1ed9faa64c95f296262bf946b6a099cc630f6c4531cbe8cba1bbff136cec829bc5bf97101481fad8e9ced8e7fbc53e049886ae7fdc447a83",
      "0xd5F5175D014F28c85F7D67A111C2c9335D7CD771"]
      )).to.not.be.reverted;
    });
    
    it("Should fail a certificate signed by a different key", async function () {
      const { xd } = await loadFixture(deployContractsFixture);
      await expect(xd.addCert(
            "0x308202cc30820273a003020102020101300a06082a8648ce3d0403023039310c300a060355040a130354454531293027060355040313203664373032613963626339613439656562633964343036663862393462623338301e170d3730303130313030303030305a170d3438303130313030303030305a301f311d301b06035504031314416e64726f6964204b657973746f7265204b65793059301306072a8648ce3d020106082a8648ce3d03010703420004be434ab043ab09658cf178a6f19c9518835d90b8dfe10f836dd00f6aae9a68c251426f075ef85f93e71b5b953101269504e216c2a1f4c36be5d75d1211782f08a382018430820180300e0603551d0f0101ff0404030207803082016c060a2b06010401d6790201110482015c30820158020200c80a0101020200c80a01010441ba21a7851ddb5b251d5c3cbfcd7b58c60385de17ba815e3bffaa60f410ed4dd86ec7970393445d1d34748fed459851e5419d00198ec1dbaff2406f536c75c6061c04003056bf853d0802060184d46f3b74bf85454604443042311c301a0415636f6d2e6578616d706c652e616e64726f6964636b020101312204207322227e0a2a9bac891e1e3fda1fc16356b8e4a417c20c419627d28f3e083bf13081aaa1053103020102a203020103a30402020100a5053103020104aa03020101bf837803020103bf8379040202012cbf853e03020100bf85404c304a04208b2c4cd539f5075e8e7cf212adb3db0413fbd77d321199c73d5a473c51f2e10d0101ff0a0100042092a169f2ac890d35022e76791565c123c56620dae3ffa41c4195e15a3f34390bbf854105020301fbd0bf85420502030315e1bf854e06020401348be9bf854f06020401348be9300a06082a8648ce3d040302034700304402207e7fed041caa2c3b931b6ea550ca5e5234fe96396e93a5552e229005481e760602202254f0d432bafb6507c68733ebefcc15b6b247dfa3ddfdc233dc33077bb1d749",
      ["0x0000000060225dea1eb30c0b1ed9faa64c95f296262bf946b6a099cc630f6c4531cbe8cba1bbff136cec829bc5bf97101481fad8e9ced8e7fbc53e049886ae7fdc447a83",
      "0x1234567890123456789012345678901234567890"]
      )).to.be.revertedWith("Invalid signature for intended address");
    });
    
    it("Should fail a software certificate", async function () {
      const { xd } = await loadFixture(deployContractsFixture);
      await expect(xd.addCert(
            "0x30820319308202c0a003020102020101300a06082a8648ce3d040302308188310b30090603550406130255533113301106035504080c0a43616c69666f726e696131153013060355040a0c0c476f6f676c652c20496e632e3110300e060355040b0c07416e64726f6964313b303906035504030c32416e64726f6964204b657973746f726520536f667477617265204174746573746174696f6e20496e7465726d656469617465301e170d3730303130313030303030305a170d3438303130313030303030305a301f311d301b06035504031314416e64726f6964204b657973746f7265204b65793059301306072a8648ce3d020106082a8648ce3d03010703420004ac7169b2f2c5bc458f5e0280f3de1567176c08aceb8408995e4e069a326803fef7ecb417d03170746627c09df62f5db61b75e6ac2d807161058b95a9c5fcd509a38201813082017d300e0603551d0f0101ff04040302078030820169060a2b06010401d6790201110482015930820155020200c80a0100020200c80a010004419ca0f1a1c98f57318073e358e54a496c329e73e5ed453f5e2a67b277e9d09d17291d607da3a061d76ac800e39270af8f344e23a45e16b0f47dd248cc315da1f01c04003081fda1053103020102a203020103a30402020100a5053103020104aa03020101bf837803020103bf8379040202012cbf853d0802060184d43f49bebf853e03020100bf85404c304a042000000000000000000000000000000000000000000000000000000000000000000101000a010204200000000000000000000000000000000000000000000000000000000000000000bf854105020301fbd0bf85420502030315e3bf85454604443042311c301a0415636f6d2e6578616d706c652e616e64726f6964636b020101312204207322227e0a2a9bac891e1e3fda1fc16356b8e4a417c20c419627d28f3e083bf1bf854e03020100bf854f06020401348cad3000300a06082a8648ce3d0403020347003044022074e7962334c9cc51c2ccfd580cc16bcf2aeb8f271d93eb164f67963a0a9450c902200be4defad08d4eb973e39b9953e035b3382bd02f2dcee82b8615e750087fac6a",
      ["0x00000000eb9e79f8426359accb2a914c8986cc70ad90669382a9732613feaccbf821274c2174974a2afea5b94d7f66d4e065106635bc53b7a0a3a671583edb3e11ae1014",
      "0x0102030405060708090a0102030405060708090a"]
      )).to.be.revertedWith("Software KeyStore not allowed; a hardware TEE is required.");
    });
  });
});
