// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

library KeystoreStorageLib {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Storage slot for the `MasterKeystoreStorage` struct.
    ///
    /// @dev Computed as specified in ERC-7201:
    ///      keccak256(abi.encode(uint256(keccak256("storage.MasterKeystore")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 constant MASTER_KEYSTORE_STORAGE_LOCATION =
        0xab0db9dff4dd1cc7cbf1b247b1f1845c685dfd323fb0c6da795f47e8940a2c00;

    /// @notice Storage slot for the `ReplicaKeystoreStorage` struct.
    ///
    /// @dev Computed as specified in ERC-7201:
    ///      keccak256(abi.encode(uint256(keccak256("storage.ReplicaKeystore")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 constant REPLICA_KEYSTORE_STORAGE_LOCATION =
        0x1db15b34d880056d333fb6d93991f1076dc9f2ab389771578344740e0968e700;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            STRUCTURES                                          //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @dev Storage layout for the Keystore on the master chain.
    ///
    /// @custom:storage-location erc7201:storage.MasterKeystore
    struct MasterKeystoreStorage {
        /// @dev Hash of the `config`.
        bytes32 configHash;
        /// @dev Nonce of the Keystore configuration.
        uint256 configNonce;
    }

    /// @dev Storage layout for the Keystore on replica chains.
    ///
    /// @custom:storage-location erc7201:storage.ReplicaKeystore
    struct ReplicaKeystoreStorage {
        /// @dev Hash of the latest synced `masterConfig`.
        bytes32 masterConfigHash;
        /// @dev Timestamp of the L1 block used to sync the latest `masterConfig`.
        uint256 masterBlockTimestamp;
        /// @dev Latest mirrored config nonce.
        uint256 currentConfigNonce;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                         HELPER FUNCTIONS                                      //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Retrieves the `MasterKeystoreStorage` struct from storage.
    function _getMasterKeystoreStorage() internal pure returns (MasterKeystoreStorage storage ms) {
        bytes32 position = MASTER_KEYSTORE_STORAGE_LOCATION;
        assembly {
            ms.slot := position
        }
    }

    /// @notice Retrieves the `ReplicaKeystoreStorage` struct from storage.
    function _getReplicaKeystoreStorage() internal pure returns (ReplicaKeystoreStorage storage rs) {
        bytes32 position = REPLICA_KEYSTORE_STORAGE_LOCATION;
        assembly {
            rs.slot := position
        }
    }
}
