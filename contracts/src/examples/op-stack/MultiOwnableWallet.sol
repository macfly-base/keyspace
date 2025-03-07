// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {IAccount} from "aa/interfaces/IAccount.sol";
import {UserOperation} from "aa/interfaces/UserOperation.sol";
import {Receiver} from "solady/accounts/Receiver.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";

import {Keystore} from "../../core/Keystore.sol";
import {ConfigLib} from "../../core/KeystoreLibs.sol";
import {OPStackKeystore} from "../../core/chains/OPStackKeystore.sol";

import {ERC1271} from "../utils/ERC1271.sol";
import {TransientUUPSUpgradeable} from "../utils/TransientUUPSUpgradeable.sol";

contract MultiOwnableWallet is OPStackKeystore, ERC1271, TransientUUPSUpgradeable, Receiver, IAccount {
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           CONSTANTS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice The EntryPoint V0.6 address.
    address constant ENTRYPOINT_ADDRESS = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    /// @notice Slot for the `WalletStorage` struct in storage.
    ///
    /// @dev Computed as specified in ERC-7201 (see https://eips.ethereum.org/EIPS/eip-7201):
    ///      keccak256(abi.encode(uint256(keccak256("storage.MultiOwnableWallet")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 constant WALLET_STORAGE_LOCATION = 0xa77adb1dc9bb40c655d8d6905390b0bccb8c0d39c0692125ebfde9aed74bd500;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                              ERRORS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Thrown when the caller is not authorized.
    error UnauthorizedCaller();

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                            STRUCTURES                                          //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @dev Storage layout used to store the Wallet data.
    ///
    /// @custom:storage-location erc7201:storage.MultiOwnableWallet
    struct WalletStorage {
        /// @dev The mapping of Keystore configs.
        ///      NOTE: Using a mapping allows to set a new entry for each new Keystore config and thus avoid the need to
        ///            to have to properly delete all the previous config.
        mapping(bytes32 configHash => KeystoreConfig) keystoreConfig;
    }

    /// @dev The Keystore config for this wallet.
    struct KeystoreConfig {
        /// @dev The wallet signers.
        mapping(address signer => bool isSigner) signers;
    }

    /// @notice Represents a call to make.
    struct Call {
        /// @dev The address to call.
        address target;
        /// @dev The value to send when making the call.
        uint256 value;
        /// @dev The data of the call.
        bytes data;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                           MODIFIERS                                            //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Ensures the caller is the EntryPoint.
    modifier onlyEntryPoint() {
        require(msg.sender == ENTRYPOINT_ADDRESS, UnauthorizedCaller());

        _;
    }

    /// @notice Ensures the caller is ether the EntryPoint, the account itself or an owner.
    modifier onlyEntryPointOrOwner() {
        require(
            msg.sender == ENTRYPOINT_ADDRESS || msg.sender == address(this) || _isOwner(msg.sender),
            UnauthorizedCaller()
        );

        _;
    }

    /// @notice Sends to the EntryPoint (i.e. `msg.sender`) the missing funds for this transaction.
    ///
    /// @param missingAccountFunds The minimum value this modifier should send the EntryPoint which
    ///                            MAY be zero, in case there is enough deposit, or the userOp has a
    ///                            paymaster.
    modifier payPrefund(uint256 missingAccountFunds) {
        _;

        assembly ("memory-safe") {
            if missingAccountFunds {
                // Ignore failure (it's EntryPoint's job to verify, not the account's).
                pop(call(gas(), caller(), missingAccountFunds, codesize(), 0x00, codesize(), 0x00))
            }
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                          CONSTRUCTOR                                           //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    constructor(uint256 masterChainId) OPStackKeystore(masterChainId) {}

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PUBLIC FUNCTIONS                                        //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Initializes the wallet.
    ///
    /// @param config The initial Keystore config.
    function initialize(ConfigLib.Config calldata config) external {
        _initializeKeystore(config);
    }

    /// @inheritdoc IAccount
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        override
        onlyEntryPoint
        payPrefund(missingAccountFunds)
        returns (uint256 validationData)
    {
        // Since the signature of the `userOp` is validated against the current Keystore config, it cannot reach the
        // execution phase if the `userOp` is signed using a Keystore config that has not yet been set. To enable such a
        // to-be-set Keystore config to proceed to the execution phase, any prepended `setConfig()` calls of an
        // `executeBatch()` call must be executed at validation time.
        _executePrependedSetConfigCalls(userOp.callData);

        // NOTE: Intentionally do not enforce EC at validation time.
        return _isValidSignature({hash: userOpHash, signature: userOp.signature}) ? 0 : 1;
    }

    /// @notice Executes the given call from this account.
    ///
    /// @dev Reverts if not called by the Entrypoint or an owner of this account (including itself).
    ///
    /// @param target The address to call.
    /// @param value The value to send with the call.
    /// @param data The data of the call.
    function execute(address target, uint256 value, bytes calldata data) external payable onlyEntryPointOrOwner {
        _call({target: target, value: value, data: data});
    }

    /// @notice Executes batch of `Call`s.
    ///
    /// @dev Reverts if not called by the Entrypoint or an owner of this account (including itself).
    ///
    /// @param calls The list of `Call`s to execute.
    function executeBatch(Call[] calldata calls) external payable virtual onlyEntryPointOrOwner {
        // Skip the prepended `setConfig()` calls that have already been executed at validation time.
        uint256 i;
        for (
            i;
            i < calls.length && _isSetConfigCall({target: calls[i].target, value: calls[i].value, data: calls[i].data});
            i++
        ) {}

        // Execute the remaining calls.
        for (i; i < calls.length; i++) {
            _call({target: calls[i].target, value: calls[i].value, data: calls[i].data});
        }
    }

    /// @inheritdoc Keystore
    function hookIsConfigValid(ConfigLib.Config calldata config, bytes calldata validationProof)
        public
        view
        override
        returns (bool)
    {
        // NOTE: Because this hook is limited to a view function, no special access control logic is required.

        bytes32 configHash = ConfigLib.hash({config: config, account: address(this)});
        (, bytes memory signatureUpdate) = abi.decode(validationProof, (bytes, bytes));
        (uint256 sigUpdateSignerIndex, bytes memory signature) = abi.decode(signatureUpdate, (uint256, bytes));

        // Perform a safeguard check to make sure the update is valid.
        (, address[] memory signers) = abi.decode(config.data, (address, address[]));
        address sigUpdateSigner = signers[sigUpdateSignerIndex];

        return
            SignatureCheckerLib.isValidSignatureNow({signer: sigUpdateSigner, hash: configHash, signature: signature});
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                       INTERNAL FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @inheritdoc ERC1271
    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        return ("MultiOwnableWallet", "1");
    }

    /// @inheritdoc ERC1271
    function _isValidSignature(bytes32 hash, bytes memory signature) internal view override returns (bool) {
        (address signer, bytes memory signature_) = abi.decode(signature, (address, bytes));

        // Ensure the signer is registered in the current Keystore config.
        if (!_isOwner(signer)) {
            return false;
        }

        // Check if the signature is valid.
        return SignatureCheckerLib.isValidSignatureNow({signer: signer, hash: hash, signature: signature_});
    }

    /// @inheritdoc Keystore
    function _hookIsConfigAuthorized(ConfigLib.Config calldata config, bytes calldata authorizationProof)
        internal
        view
        override
        returns (bool)
    {
        bytes32 configHash = ConfigLib.hash({config: config, account: address(this)});
        (bytes memory signatureAuth,) = abi.decode(authorizationProof, (bytes, bytes));

        // Ensure the update is authorized.
        return _isValidSignature({hash: configHash, signature: signatureAuth});
    }

    /// @inheritdoc Keystore
    function _hookApplyConfig(ConfigLib.Config calldata config) internal override returns (bool) {
        // NOTE: Only decode the implementation as we don't know if an uprade will be performed or not yet.
        address implementation = abi.decode(config.data, (address));

        // Read the current implementation and if it changed perform the upgrade.
        address currentImpl;
        assembly {
            currentImpl := sload(_ERC1967_IMPLEMENTATION_SLOT)
        }

        if (implementation != currentImpl) {
            _allowUpgrade();

            // NOTE: Must be a public call as `upgradeToAndCall` accepts a `bytes calldata data`.
            (, bytes memory data) = abi.decode(config.data, (address, bytes));
            this.upgradeToAndCall({newImplementation: implementation, data: data});
            return true;
        }

        // Otherwise set the new signers.
        (, address[] memory signers) = abi.decode(config.data, (address, address[]));
        bytes32 configHash = ConfigLib.hash({config: config, account: address(this)});
        mapping(address signer => bool isSigner) storage signers_ = _sWallet().keystoreConfig[configHash].signers;
        for (uint256 i; i < signers.length; i++) {
            signers_[signers[i]] = true;
        }

        return false;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //                                        PRIVATE FUNCTIONS                                       //
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    /// @notice Helper function to get a storage reference to the `WalletStorage` struct.
    ///
    /// @return $ A storage reference to the `WalletStorage` struct.
    function _sWallet() private pure returns (WalletStorage storage $) {
        bytes32 position = WALLET_STORAGE_LOCATION;
        assembly ("memory-safe") {
            $.slot := position
        }
    }

    /// @notice Returns true if the provided `addr` is an owner.
    ///
    /// @param addr The address to check.
    ///
    /// @return True if the provided `addr` is an owner, otherwise false.
    function _isOwner(address addr) private view returns (bool) {
        bytes32 currentConfigHash = _currentConfigHash();
        KeystoreConfig storage config = _sWallet().keystoreConfig[currentConfigHash];
        return config.signers[addr];
    }

    /// @notice Checks if the provided call correspond to a `setConfig()` call.
    ///
    /// @param target The target call address.
    /// @param value The call value to user.
    /// @param data The raw call data.
    ///
    /// @return `true` if the call is a `setConfig()` call, otherwise `false`.
    function _isSetConfigCall(address target, uint256 value, bytes memory data) private view returns (bool) {
        return target == address(this) && bytes4(data) == this.setConfig.selector && value == 0;
    }

    /// @notice Executes all the prepended `setConfig()` calls of an `executeBatch()` call until the first
    ///         non-`setConfig()` call.
    ///
    /// @param userOpCallData The UserOp calldata.
    function _executePrependedSetConfigCalls(bytes calldata userOpCallData) private {
        // Early return if the call is not an `executeBatch()`.
        if (bytes4(userOpCallData) != this.executeBatch.selector) {
            return;
        }

        // Execute all the `setConfig()` calls until we reach the first non-`setConfig()` call.
        Call[] memory calls = abi.decode(userOpCallData[4:], (Call[]));
        for (uint256 i; i < calls.length; i++) {
            Call memory call = calls[i];

            if (!_isSetConfigCall({target: call.target, value: call.value, data: call.data})) {
                break;
            }

            // TODO: Might be more gas efficient to make `setConfig()` public and directly do an internal call here.
            _call({target: call.target, value: call.value, data: call.data});
        }
    }

    /// @notice Executes the given call from this account.
    ///
    /// @dev Reverts if the call reverted.
    /// @dev Implementation taken from
    ///      https://github.com/alchemyplatform/light-account/blob/43f625afdda544d5e5af9c370c9f4be0943e4e90/src/common/BaseLightAccount.sol#L125
    ///
    /// @param target The target call address.
    /// @param value The call value to user.
    /// @param data The raw call data.
    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
    }
}
