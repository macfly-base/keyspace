// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Keystore} from "../../core/Keystore.sol";

import {KeystoreArbitrumPortal} from "./portals/KeystoreArbitrumPortal.sol";
import {KeystoreBasePortal} from "./portals/KeystoreBasePortal.sol";
import {KeystoreOptimismPortal} from "./portals/KeystoreOptimismPortal.sol";

import {BinaryMerkleTreeLib} from "./state/BinaryMerkleTreeLib.sol";
import {KeystoreBridgeStorageLib} from "./state/KeystoreBridgeStorageLib.sol";

contract KeystoreBridge is KeystoreArbitrumPortal, KeystoreBasePortal, KeystoreOptimismPortal {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PUBLIC FUNCTIONS                                        //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Retrieves the received root for a given origin chain id.
    ///
    /// @param originChainid The origin chain id.
    ///
    /// @return The received root.
    function receivedRoot(uint256 originChainid) external view returns (bytes32) {
        return KeystoreBridgeStorageLib.receivedRoot(originChainid);
    }

    /// @notice Retrieves the local root.
    ///
    /// @return The local root.
    function localRoot() external view returns (bytes32) {
        return KeystoreBridgeStorageLib.localRoot();
    }

    /// @notice Commits Keystore configs to the local Merkle Tree.
    ///
    /// @param keystores An array of Keystore addresses whose configs will be committed.
    function commitToConfigs(address[] calldata keystores) external {
        BinaryMerkleTreeLib.Tree storage tree = KeystoreBridgeStorageLib.sKeystoreBridge()._tree;

        for (uint256 i; i < keystores.length; i++) {
            address keystore = keystores[i];
            (bytes32 masterConfigHash, uint256 masterBlockTimestamp) = Keystore(keystore).masterConfigHashAndTimestamp();

            BinaryMerkleTreeLib.commitTo({
                tree: tree,
                // NOTE: The `dataHash` must commit to the `keystore` address, as it could potentially be malicious and
                //       return an arbitrary `masterConfigHash`.
                dataHash: keccak256(abi.encodePacked(keystore, masterConfigHash, masterBlockTimestamp))
            });
        }
    }
}
