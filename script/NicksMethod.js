const fs = require("fs");
const { ethers } = require("ethers");
const DESIRED_ADDRESS_PREFIX = "271828";

(async () => {
    const provider = new ethers.JsonRpcProvider("http://127.0.0.1:8545");
    await provider.getBlock();

    if (process.argv.length !== 3 || process.argv[2]?.slice(-4) !== ".sol") {
        console.log('Usage: node NicksMethod.js <fileName>.sol');
        process.exit(1);
    }
    
    const fileName = process.argv[2];
    const artifact = require("../out/" + fileName + `/${fileName.slice(0, -4)}.json`);
    const factory = ethers.ContractFactory.fromSolidity(artifact);
    const deploymentTx = await factory.getDeployTransaction();
    const legacyTx = {
        nonce: 0,
        gasPrice: ethers.parseUnits("100", "gwei"),
        gasLimit: await provider.estimateGas(deploymentTx),
        value: 0,
        data: deploymentTx.data
    }

    let tx = { ...legacyTx, v: "0x1b" };
    let contractAddress;
    while (contractAddress?.slice(2, 2 + DESIRED_ADDRESS_PREFIX.length) !== DESIRED_ADDRESS_PREFIX) {
        tx.r = ethers.hexlify(ethers.randomBytes(32));
        tx.s = ethers.hexlify(ethers.randomBytes(32));

        try {
            tx.from = ethers.recoverAddress(
                ethers.Transaction.from(legacyTx).unsignedHash,
                {
                    v: tx.v,
                    r: tx.r,
                    s: tx.s
                }
            );

            contractAddress = ethers.getCreateAddress(tx);
        } catch {}
    }

    const finalTx = ethers.Transaction.from(legacyTx)
    finalTx.signature = {
        v: tx.v,
        r: tx.r,
        s: tx.s
    }
    
    console.log("contractAddress: " + contractAddress);
    console.log("deployerAddress: " + tx.from);
    console.log("gasLimit: " + tx.gasLimit.toString());
    console.log("gasPrice: " + tx.gasPrice.toString());
    fs.writeFileSync("./NicksMethodResult.txt", finalTx.serialized);
})()
