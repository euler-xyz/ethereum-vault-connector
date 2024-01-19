// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Importing Forge standard library's Script module
import "forge-std/Script.sol";
// Importing the EthereumVaultConnector contract
import "../src/EthereumVaultConnector.sol";


/// @title DeployEthereumVaultConnector
/// @notice This script is used for deterministically deploying the
/// EthereumVaultConnector contract accross different chains.
/// @dev Run this script with the following command:
///      forge script script/deploy.s.sol:DeployEthereumVaultConnector \
///      --rpc-url <your_rpc_url> --etherscan-api-key <your_etherscan_api_key> \ 
///      --broadcast --verify -vvvv
/// It requires the PRIVATE_KEY to be set as environment variable.
contract DeployEthereumVaultConnector is Script {
     /// @notice Main function that executes the deployment process
     /// @dev This function reads the private key from environment variables, 
     ///      initializes broadcasting, and deploys the EthereumVaultConnector contract.
     ///      It also handles the broadcast stoppage after deployment.
    function run() public {
        // Fetching the private key from environment variable
        uint privateKey = vm.envUint("PRIVATE_KEY");
        // Setting a zero bytes32 salt for deterministic deployment. 
        // It can also be the version number.
        bytes32 versionSalt = bytes32(0);

        // Starting the broadcast transaction process with the provided private key
        vm.startBroadcast(privateKey);
        // Deploying the EthereumVaultConnector contract with specified deployment salt
        new EthereumVaultConnector{salt: versionSalt}();

        // Stopping the broadcast process
        vm.stopBroadcast();
    }
}
