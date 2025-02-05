// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {Keystore} from "../../core/Keystore.sol";
import {ConfigLib} from "../../core/KeystoreLibs.sol";

import {BinaryMerkleTreeLib} from "./state/BinaryMerkleTreeLib.sol";

import {KeystoreBridge} from "./KeystoreBridge.sol";

abstract contract KeystoreBridgeableExt is Keystore {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The address of the `KeystoreBridge` contract.
    address public immutable keystoreBridge;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when the master Keystore config Merkle proof verification fails against the `KeystoreBridge`
    ///         received root.
    error InvalidKeystoreConfigMerkleProof();

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                          CONSTRUCTOR                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Constructor.
    ///
    /// @param keystoreBridge_ The address of the `KeystoreBridge` contract.
    constructor(address keystoreBridge_) {
        keystoreBridge = keystoreBridge_;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PUBLIC FUNCTIONS                                        //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Syncs a master Keystore config from the `KeystoreBridge` contract.
    ///
    /// @param masterConfig The master config to sync.
    /// @param masterBlockTimestamp The block timestamp for the `masterConfig`.
    /// @param index The index of the leaf in the Merkle tree.
    /// @param siblings The Merkle proof sibling hashes.
    function syncConfigFromBridge(
        ConfigLib.Config calldata masterConfig,
        uint256 masterBlockTimestamp,
        uint256 index,
        bytes32[] calldata siblings
    ) external {
        // Retrieve the received root from the bridge.
        bytes32 receivedRoot = KeystoreBridge(keystoreBridge).receivedRoot(masterChainId);

        // Recompute the data hash that was committed in the root.
        bytes32 masterConfigHash = ConfigLib.hash({config: masterConfig, account: address(this)});

        // Ensure the provided `masterConfig` and `masterBlockTimestamp` are valid for this Keystore contract.
        require(
            BinaryMerkleTreeLib.isValid({
                root_: receivedRoot,
                // NOTE: Ensure that the `dataHash` commits to `address(this)`, proving that `masterConfigHash` was
                //       effectively fetched from this contract on the master chain.
                dataHash: keccak256(abi.encodePacked(address(this), masterConfigHash, masterBlockTimestamp)),
                index: index,
                siblings: siblings
            }),
            InvalidKeystoreConfigMerkleProof()
        );

        // Ensure we are going forward when syncing a master config.
        (, uint256 currentMasterBlockTimestamp) = masterConfigHashAndTimestamp();
        require(
            masterBlockTimestamp > currentMasterBlockTimestamp,
            MasterConfigOutdated({
                currentMasterBlockTimestamp: currentMasterBlockTimestamp,
                newMasterBlockTimestamp: masterBlockTimestamp
            })
        );

        // Apply the master config to the Keystore storage.
        _applyMasterConfig({
            masterConfigHash: masterConfigHash,
            masterConfig: masterConfig,
            masterBlockTimestamp: masterBlockTimestamp
        });
    }
}
