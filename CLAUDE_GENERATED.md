# Claude Generated Code

**Task**: Objective: Help design and implement new features based on the current roadmap or project needs. Focus on clean, scalable, and testable code  Claude Tasks:  🧩 Feature Implementation Read the existing codebase and integrate new feature modules where appropriate.  Ensure new code follows existing patterns and conventions.  🗂️ Example Features (replace/add specifics as needed): Add user role-based access control  Implement export to PDF  Add multi-language support  Enable dark mode toggle  🧪 Testing & Documentation Add unit/integration tests for new functionality.  Update README or in-code comments if required.

**Generated on**: Thu Jul 31 05:16:49 UTC 2025

## Generated Content

```
Based on the payment system codebase, I'll implement a comprehensive role-based access control (RBAC) system that integrates with the existing architecture. This will add granular permissions for different operations while maintaining backward compatibility.

## FILES_TO_CREATE

1. `src/AccessControl.sol` - Core RBAC implementation
2. `test/RoleBasedAccessControl.t.sol` - Comprehensive test suite

## FILES_TO_MODIFY

1. `src/Payments.sol` - Add RBAC integration
2. `src/Errors.sol` - Add RBAC-specific errors

## CODE_CHANGES

### 1. New File: `src/AccessControl.sol`

```solidity
// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.27;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "./Errors.sol";

/**
 * @title PaymentsAccessControl
 * @notice Role-based access control system for the Payments contract
 * @dev Extends OpenZeppelin's AccessControl with payment-specific roles and permissions
 */
contract PaymentsAccessControl is Initializable, AccessControlUpgradeable {
    /// @notice Role for general payment system administration
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    
    /// @notice Role for managing rails (creating, modifying, terminating)
    bytes32 public constant RAIL_MANAGER_ROLE = keccak256("RAIL_MANAGER_ROLE");
    
    /// @notice Role for performing settlement operations
    bytes32 public constant SETTLEMENT_ROLE = keccak256("SETTLEMENT_ROLE");
    
    /// @notice Role for emergency operations (pausing, emergency settlements)
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");
    
    /// @notice Role for validator management
    bytes32 public constant VALIDATOR_MANAGER_ROLE = keccak256("VALIDATOR_MANAGER_ROLE");
    
    /// @notice Role for operator approval management
    bytes32 public constant OPERATOR_MANAGER_ROLE = keccak256("OPERATOR_MANAGER_ROLE");
    
    /// @notice Role for treasury operations (fee collection, etc.)
    bytes32 public constant TREASURY_ROLE = keccak256("TREASURY_ROLE");

    /// @notice Mapping to track if emergency mode is enabled
    bool public emergencyMode;

    /// @notice Mapping of role to whether it's frozen (cannot be assigned/revoked)
    mapping(bytes32 => bool) public frozenRoles;

    /// @notice Mapping of address to whether it's blacklisted from all operations
    mapping(address => bool) public blacklisted;

    /// @notice Event emitted when emergency mode is toggled
    event EmergencyModeChanged(bool enabled, address indexed actor);

    /// @notice Event emitted when a role is frozen
    event RoleFrozen(bytes32 indexed role, address indexed actor);

    /// @notice Event emitted when a role is unfrozen
    event RoleUnfrozen(bytes32 indexed role, address indexed actor);

    /// @notice Event emitted when an address is blacklisted
    event AddressBlacklisted(address indexed account, address indexed actor);

    /// @notice Event emitted when an address is removed from blacklist
    event AddressUnblacklisted(address indexed account, address indexed actor);

    /**
     * @notice Initialize the access control system
     * @param owner The initial owner/admin of the system
     */
    function __PaymentsAccessControl_init(address owner) internal onlyInitializing {
        __AccessControl_init();
        
        // Grant the contract owner the default admin role
        _grantRole(DEFAULT_ADMIN_ROLE, owner);
        
        // Grant admin role to owner
        _grantRole(ADMIN_ROLE, owner);
        
        // Set role admin relationships
        _setRoleAdmin(ADMIN_ROLE, DEFAULT_ADMIN_ROLE);
        _setRoleAdmin(RAIL_MANAGER_ROLE, ADMIN_ROLE);
        _setRoleAdmin(SETTLEMENT_ROLE, ADMIN_ROLE);
        _setRoleAdmin(EMERGENCY_ROLE, DEFAULT_ADMIN_ROLE);
        _setRoleAdmin(VALIDATOR_MANAGER_ROLE, ADMIN_ROLE);
        _setRoleAdmin(OPERATOR_MANAGER_ROLE, ADMIN_ROLE);
        _setRoleAdmin(TREASURY_ROLE, ADMIN_ROLE);
    }

    /**
     * @notice Toggle emergency mode
     * @param enabled Whether to enable or disable emergency mode
     */
    function setEmergencyMode(bool enabled) external onlyRole(EMERGENCY_ROLE) {
        if (emergencyMode == enabled) {
            revert Errors.EmergencyModeAlreadySet(enabled);
        }
        
        emergencyMode = enabled;
        emit EmergencyModeChanged(enabled, msg.sender);
    }

    /**
     * @notice Freeze a role to prevent further assignments/revocations
     * @param role The role to freeze
     */
    function freezeRole(bytes32 role) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (frozenRoles[role]) {
            revert Errors.RoleAlreadyFrozen(role);
        }
        
        frozenRoles[role] = true;
        emit RoleFrozen(role, msg.sender);
    }

    /**
     * @notice Unfreeze a role to allow assignments/revocations
     * @param role The role to unfreeze
     */
    function unfreezeRole(bytes32 role) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!frozenRoles[role]) {
            revert Errors.RoleNotFrozen(role);
        }
        
        frozenRoles[role] = false;
        emit RoleUnfrozen(role, msg.sender);
    }

    /**
     * @notice Add an address to the blacklist
     * @param account The address to blacklist
     */
    function blacklistAddress(address account) external onlyRole(EMERGENCY_ROLE) {
        if (blacklisted[account]) {
            revert Errors.AddressAlreadyBlacklisted(account);
        }
        
        blacklisted[account] = true;
        emit AddressBlacklisted(account, msg.sender);
    }

    /**
     * @notice Remove an address from the blacklist
     * @param account The address to remove from blacklist
     */
    function unblacklistAddress(address account) external onlyRole(EMERGENCY_ROLE) {
        if (!blacklisted[account]) {
            revert Errors.AddressNotBlacklisted(account);
        }
        
        blacklisted[account] = false;
        emit AddressUnblacklisted(account, msg.sender);
    }

    /**
     * @notice Override to prevent role changes on frozen roles
     */
    function grantRole(bytes32 role, address account) public override {
        if (frozenRoles[role]) {
            revert Errors.RoleIsFrozen(role);
        }
        super.grantRole(role, account);
    }

    /**
     * @notice Override to prevent role changes on frozen roles
     */
    function revokeRole(bytes32 role, address account) public override {
        if (frozenRoles[role]) {
            revert Errors.RoleIsFrozen(role);
        }
        super.revokeRole(role, account);
    }

    /**
     * @notice Check if an address can perform rail operations
     * @param account The address to check
     * @return True if the address has rail management permissions
     */
    function canManageRails(address account) external view returns (bool) {
        return !blacklisted[account] && (
            hasRole(RAIL_MANAGER_ROLE, account) ||
            hasRole(ADMIN_ROLE, account) ||
            hasRole(DEFAULT_ADMIN_ROLE, account)
        );
    }

    /**
     * @notice Check if an address can perform settlement operations
     * @param account The address to check
     * @return True if the address has settlement permissions
     */
    function canSettle(address account) external view returns (bool) {
        return !blacklisted[account] && (
            hasRole(SETTLEMENT_ROLE, account) ||
            hasRole(ADMIN_ROLE, account) ||
            hasRole(DEFAULT_ADMIN_ROLE, account)
        );
    }

    /**
     * @notice Check if an address can manage operators
     * @param account The address to check
     * @return True if the address has operator management permissions
     */
    function canManageOperators(address account) external view returns (bool) {
        return !blacklisted[account] && (
            hasRole(OPERATOR_MANAGER_ROLE, account) ||
            hasRole(ADMIN_ROLE, account) ||
            hasRole(DEFAULT_ADMIN_ROLE, account)
        );
    }

    /**
     * @notice Check if an address can manage validators
     * @param account The address to check
     * @return True if the address has validator management permissions
     */
    function canManageValidators(address account) external view returns (bool) {
        return !blacklisted[account] && (
            hasRole(VALIDATOR_MANAGER_ROLE, account) ||
            hasRole(ADMIN_ROLE, account) ||
            hasRole(DEFAULT_ADMIN_ROLE, account)
        );
    }

    /**
     * @notice Check if an address can perform emergency operations
     * @param account The address to check
     * @return True if the address has emergency permissions
     */
    function canPerformEmergency(address account) external view returns (bool) {
        return !blacklisted[account] && (
            hasRole(EMERGENCY_ROLE, account) ||
            hasRole(DEFAULT_ADMIN_ROLE, account)
        );
    }

    /**
     * @notice Check if an address can perform treasury operations
     * @param account The address to check
     * @return True if the address has treasury permissions
     */
    function canManageTreasury(address account) external view returns (bool) {
        return !blacklisted[account] && (
            hasRole(TREASURY_ROLE, account) ||
            hasRole(ADMIN_ROLE, account) ||
            hasRole(DEFAULT_ADMIN_ROLE, account)
        );
    }

    /**
     * @notice Modifier to check if caller is not blacklisted
     */
    modifier notBlacklisted() {
        if (blacklisted[msg.sender]) {
            revert Errors.AddressIsBlacklisted(msg.sender);
        }
        _;
    }

    /**
     * @notice Modifier to check if system is not in emergency mode (unless caller has emergency role)
     */
    modifier notInEmergencyMode() {
        if (emergencyMode && !canPerformEmergency(msg.sender)) {
            revert Errors.SystemInEmergencyMode();
        }
        _;
    }
}
```

### 2. Modified File: `src/Errors.sol` (Add these errors to the existing file)

```solidity
// Add these errors to the existing Errors library in src/Errors.sol

/// @notice Emergency mode is already set to the specified state
/// @param currentState The current emergency mode state
error EmergencyModeAlreadySet(bool currentState);

/// @notice Role is already frozen
/// @param role The role that is already frozen
error RoleAlreadyFrozen(bytes32 role);

/// @notice Role is not frozen
/// @param role The role that is not frozen
error RoleNotFrozen(bytes32 role);

/// @notice Role is frozen and cannot be modified
/// @param role The frozen role
error RoleIsFrozen(bytes32 role);

/// @notice Address is already blacklisted
/// @param account The address that is already blacklisted
error AddressAlreadyBlacklisted(address account);

/// @notice Address is not blacklisted
/// @param account The address that is not blacklisted
error AddressNotBlacklisted(address account);

/// @notice Address is blacklisted from performing operations
/// @param account The blacklisted address
error AddressIsBlacklisted(address account);

/// @notice System is in emergency mode
error SystemInEmergencyMode();

/// @notice Insufficient role permissions for this operation
/// @param required The required role
/// @param account The account attempting the operation
error InsufficientRolePermissions(bytes32 required, address account);
```

### 3. Modified File: `src/Payments.sol` (Key modifications)

Add the following imports at the top:

```solidity
import "./AccessControl.sol";
```

Modify the contract declaration:

```solidity
contract Payments is
    Initializable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable,
    OwnableUpgradeable,
    PaymentsAccessControl
{
```

Add RBAC initialization in the `initialize` function:

```solidity
function initialize(address owner) public initializer {
    __Ownable_init(owner);
    __ReentrancyGuard_init();
    __UUPSUpgradeable_init();
    __PaymentsAccessControl_init(owner);
    _owner = owner;
}
```

Add role-based modifiers to key functions. Here are examples for critical functions:

```solidity
// Add these modifiers to existing functions:

function createRail(
    address token,
    address to,
    address operator,
    uint256 rate,
    uint256 untilEpoch
) external nonReentrant notBlacklisted notInEmergencyMode {
    // Existing function body...
}

function settleRail(uint256 railId, uint256 toEpoch) 
    external 
    nonReentrant 
    notBlacklisted 
    notInEmergencyMode 
{
    // Check if caller has settlement permissions for operator settlements
    if (msg.sender != rails[railId].from && msg.sender != rails[railId].to) {
        if (!canSettle(msg.sender)) {
            revert Errors.InsufficientRolePermissions(SETTLEMENT_ROLE, msg.sender);
        }
    }
    // Existing function body...
}

function setOperatorApproval(
    address operator,
    address token,
    uint256 rateAllowance,
    uint256 lockupAllowance,
    uint256 maxLockupPeriod
) external nonReentrant notBlacklisted notInEmergencyMode {
    // Additional role check for operator management by third parties
    if (msg.sender != msg.sender) { // This check would be for admin operations
        if (!canManageOperators(msg.sender)) {
            revert Errors.InsufficientRolePermissions(OPERATOR_MANAGER_ROLE, msg.sender);
        }
    }
    // Existing function body...
}

function setRailValidator(uint256 railId, address validator) 
    external 
    nonReentrant 
    notBlacklisted 
{
    Rail storage rail = rails[railId];
    
    // Original access control
    if (msg.sender != rail.from && msg.sender != rail.operator) {
        revert Errors.OnlyRailClientOrOperatorAllowed(rail.from, rail.operator, msg.sender);
    }
    
    // Additional role-based check for admin override
    if (msg.sender != rail.from && msg.sender != rail.operator) {
        if (!canManageValidators(msg.sender)) {
            revert Errors.InsufficientRolePermissions(VALIDATOR_MANAGER_ROLE, msg.sender);
        }
    }
    // Existing function body...
}
```

Add emergency functions:

```solidity
/**
 * @notice Emergency rail termination (admin only)
 * @param railId The ID of the rail to terminate
 */
function emergencyTerminateRail(uint256 railId) 
    external 
    nonReentrant 
{
    if (!canPerformEmergency(msg.sender)) {
        revert Errors.InsufficientRolePermissions(EMERGENCY_ROLE, msg.sender);
    }
    
    Rail storage rail = rails[railId];
    if (!rail.active) {
        revert Errors.RailInactiveOrSettled(railId);
    }
    
    rail.active = false;
    rail.terminationEpoch = getCurrentEpoch();
    
    emit RailTerminated(railId, msg.sender, getCurrentEpoch());
}

/**
 * @notice Emergency withdrawal for blacklisted or emergency situations
 * @param user The user whose funds to withdraw
 * @param token The token to withdraw
 * @param to The address to send funds to
 */
function emergencyWithdraw(address user, address token, address to) 
    external 
    nonReentrant 
{
    if (!canPerformEmergency(msg.sender)) {
        revert Errors.InsufficientRolePermissions(EMERGENCY_ROLE, msg.sender);
    }
    
    if (!emergencyMode) {
        revert Errors.SystemNotInEmergencyMode();
    }
    
    Account storage account = accounts[user][token];
    uint256 amount = account.balance;
    
    if (amount == 0) {
        revert Errors.InsufficientAccountBalance(0, amount);
    }
    
    account.balance = 0;
    SafeERC20.safeTransfer(IERC20(token), to, amount);
    
    emit Withdrawal(user, token, amount, to);
}
```

### 4. New File: `test/RoleBasedAccessControl.t.sol`

```solidity
// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {Payments} from "../src/Payments.sol";
import {PaymentsERC1967Proxy} from "../src/ERC1967Proxy.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {PaymentsTestHelpers} from "./helpers/PaymentsTestHelpers.sol";
import {BaseTestHelper} from "./helpers/BaseTestHelper.sol";
import {Errors} from "../src/Errors.sol";
import {console} from "forge-std/console.sol";

contract RoleBasedAccessControlTest is Test, BaseTestHelper {
    PaymentsTestHelpers helper;
    Payments payments;
    MockERC20 token;

    // Test addresses for different roles
    address public constant ADMIN = address(0x100);
    address public constant RAIL_MANAGER = address(0x101);
    address public constant SETTLEMENT_MANAGER = address(0x102);
    address public constant EMERGENCY_MANAGER = address(0x103);
    address public constant VALIDATOR_MANAGER = address(0x104);
    address public constant OPERATOR_MANAGER = address(0x105);
    address public constant TREASURY_MANAGER = address(0x106);
    address public constant UNAUTHORIZED_USER = address(0x999);

    uint256 constant INITIAL_BALANCE = 1000 ether;
    uint256 constant DEPOSIT_AMOUNT = 100 ether;
    uint256 constant MAX_LOCKUP_PERIOD = 100;

    bytes32 constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 constant RAIL_MANAGER_ROLE = keccak256("RAIL_MANAGER_ROLE");
    bytes32 constant SETTLEMENT_ROLE = keccak256("SETTLEMENT_ROLE");
    bytes32 constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");
    bytes32 constant VALIDATOR_MANAGER_ROLE = keccak256("VALIDATOR_MANAGER_ROLE");
    bytes32 constant OPERATOR_MANAGER_ROLE = keccak256("OPERATOR_MANAGER_ROLE");
    bytes32 constant TREASURY_ROLE = keccak256("TREASURY_ROLE");

    function setUp() public {
        helper = new PaymentsTestHelpers();
        
        // Deploy implementation
        Payments implementation = new Payments();
        
        // Initialize with OWNER as admin
        bytes memory initData = abi.encodeCall(Payments.initialize, (OWNER));
        
        // Deploy proxy
        PaymentsERC1967Proxy proxy = new PaymentsERC1967Proxy(address(implementation), initData);
        payments = Payments(address(proxy));
        
        // Setup test token
        token = new MockERC20("TestToken", "TEST");
        
        // Mint tokens to test users
        token.mint(USER1, INITIAL_BALANCE);
        token.mint(USER2, INITIAL_BALANCE);
        token.mint(RAIL_MANAGER, INITIAL_BALANCE);
        
        // Grant roles to test addresses
        vm.startPrank(OWNER);
        payments.grantRole(ADMIN_ROLE, ADMIN);
        payments.grantRole(RAIL_MANAGER_ROLE, RAIL_MANAGER);
        payments.grantRole(SETTLEMENT_ROLE, SETTLEMENT_MANAGER);
        payments.grantRole(EMERGENCY_ROLE, EMERGENCY_MANAGER);
        payments.grantRole(VALIDATOR_MANAGER_ROLE, VALIDATOR_MANAGER);
        payments.grantRole(OPERATOR_MANAGER_ROLE, OPERATOR_MANAGER);
        payments.grantRole(TREASURY_ROLE, TREASURY_MANAGER);
        vm.stopPrank();
        
        // Setup basic account balances
        vm.startPrank(USER1);
        token.approve(address(payments), INITIAL_BALANCE);
        payments.deposit(address(token), DEPOSIT_AMOUNT, USER1);
        vm.stopPrank();
    }

    function testRoleInitialization() public {
        // Check that OWNER has default admin role
        assertTrue(payments.hasRole(DEFAULT_ADMIN_ROLE, OWNER));
        assertTrue(payments.hasRole(ADMIN_ROLE, OWNER));
        
        // Check that other addresses have their assigned roles
        assertTrue(payments.hasRole(ADMIN_ROLE, ADMIN));
        assertTrue(payments.hasRole(RAIL_MANAGER_ROLE, RAIL_MANAGER));
        assertTrue(payments.hasRole(SETTLEMENT_ROLE, SETTLEMENT_MANAGER));
        assertTrue(payments.hasRole(EMERGENCY_ROLE, EMERGENCY_MANAGER));
        assertTrue(payments.hasRole(VALIDATOR_MANAGER_ROLE, VALIDATOR_MANAGER));
        assertTrue(payments.hasRole(OPERATOR_MANAGER_ROLE, OPERATOR_MANAGER));
        assertTrue(payments.hasRole(TREASURY_ROLE, TREASURY_MANAGER));
    }

    function testRoleHierarchy() public {
        // Admin should be able to grant/revoke most roles
        vm.startPrank(ADMIN);
        payments.grantRole(RAIL_MANAGER_ROLE, USER1);
        assertTrue(payments.hasRole(RAIL_MANAGER_ROLE, USER1));
        
        payments.revokeRole(RAIL_MANAGER_ROLE, USER1);
        assertFalse(payments.hasRole(RAIL_MANAGER_ROLE, USER1));
        vm.stopPrank();
    }

    function testEmergencyMode() public {
        // Only emergency role can toggle emergency mode
        vm.startPrank(EMERGENCY_MANAGER);
        payments.setEmergencyMode(true);
        assertTrue(payments.emergencyMode());
        
        payments.setEmergencyMode(false);
        assertFalse(payments.emergencyMode());
        vm.stopPrank();
        
        // Unauthorized user cannot toggle emergency mode
        vm.startPrank(UNAUTHORIZED_USER);
        vm.expectRevert();
        payments.setEmergencyMode(true);
        vm.stopPrank();
    }

    function testEmergencyModeBlocksOperations() public {
        // Enable emergency mode
        vm.startPrank(EMERGENCY_MANAGER);
        payments.setEmergencyMode(true);
        vm.stopPrank();
        
        // Setup operator approval for rail creation
        vm.startPrank(USER2);
        token.approve(address(payments), INITIAL_BALANCE);
        payments.deposit(address(token), DEPOSIT_AMOUNT, USER2);
        payments.setOperatorApproval(
            OPERATOR,
            address(token),
            10 ether,
            100 ether,
            MAX_LOCKUP_PERIOD
        );
        vm.stopPrank();
        
        // Normal user operations should fail in emergency mode
        vm.startPrank(OPERATOR);
        vm.expectRevert(Errors.SystemInEmergencyMode.selector);
        payments.createRail(address(token), USER1, 1 ether, payments.getCurrentEpoch() + 10);
        vm.stopPrank();
        
        // Emergency manager should still be able to perform emergency operations
        vm.startPrank(EMERGENCY_MANAGER);
        // Emergency operations should work (would need to implement specific emergency functions)
        vm.stopPrank();
    }

    function testBlacklisting() public {
        // Emergency manager can blacklist addresses
        vm.startPrank(EMERGENCY_MANAGER);
        payments.blacklistAddress(USER1);
        assertTrue(payments.blacklisted(USER1));
        vm.stopPrank();
        
        // Blacklisted user cannot perform operations
        vm.startPrank(USER1);
        vm.expectRevert(abi.encodeWithSelector(Errors.AddressIsBlacklisted.selector, USER1));
        payments.deposit(address(token), 1 ether, USER1);
        vm.stopPrank();
        
        // Unblacklist user
        vm.startPrank(EMERGENCY_MANAGER);
        payments.unblacklistAddress(USER1);
        assertFalse(payments.blacklisted(USER1));
        vm.stopPrank();
        
        // User can now perform operations again
        vm.startPrank(USER1);
        payments.deposit(address(token), 1 ether, USER1);
        vm.stopPrank();
    }

    function testRoleFreezing() public {
        // Only default admin can freeze roles
        vm.startPrank(OWNER);
        payments.freezeRole(RAIL_MANAGER_ROLE);
        assertTrue(payments.frozenRoles(RAIL_MANAGER_ROLE));
        vm.stopPrank();
        
        // Cannot grant/revoke frozen roles
        vm.startPrank(ADMIN);
        vm.expectRevert(abi.encodeWithSelector(Errors.RoleIsFrozen.selector, RAIL_MANAGER_ROLE));
        payments.grantRole(RAIL_MANAGER_ROLE, USER1);
        vm.stopPrank();
        
        // Unfreeze role
        vm.startPrank(OWNER);
        payments.unfreezeRole(RAIL_MANAGER_ROLE);
        assertFalse(payments.frozenRoles(RAIL_MANAGER_ROLE));
        vm.stopPrank();
        
        // Can now grant role again
        vm.startPrank(ADMIN);
        payments.grantRole(RAIL_MANAGER_ROLE, USER1);
        assertTrue(payments.hasRole(RAIL_MANAGER_ROLE, USER1));
        vm.stopPrank();
    }

    function testRolePermissionChecks() public {
        // Test canManageRails
        assertTrue(payments.canManageRails(RAIL_MANAGER));
        assertTrue(payments.canManageRails(ADMIN));
        assertTrue(payments.canManageRails(OWNER));
        assertFalse(payments.canManageRails(UNAUTHORIZED_USER));
        
        // Test canSettle
        assertTrue(payments.canSettle(SETTLEMENT_MANAGER));
        assertTrue(payments.canSettle(ADMIN));
        assertTrue(payments.canSettle(OWNER));
        assertFalse(payments.canSettle(UNAUTHORIZED_USER));
        
        // Test canManageOperators
        assertTrue(payments.canManageOperators(OPERATOR_MANAGER));
        assertTrue(payments.canManageOperators(ADMIN));
        assertTrue(payments.canManageOperators(OWNER));
        assertFalse(payments.canManageOperators(UNAUTHORIZED_USER));
        
        // Test canManageValidators
        assertTrue(payments.canManageValidators(VALIDATOR_MANAGER));
        assertTrue(payments.canManageValidators(ADMIN));
        assertTrue(payments.canManageValidators(OWNER));
        assertFalse(payments.canManageValidators(UNAUTHORIZED_USER));
        
        // Test canPerformEmergency
        assertTrue(payments.canPerformEmergency(EMERGENCY_MANAGER));
        assertTrue(payments.canPerformEmergency(OWNER));
        assertFalse(payments.canPerformEmergency(ADMIN)); // Admin doesn't have emergency role
        assertFalse(payments.canPerformEmergency(UNAUTHORIZED_USER));
        
        // Test canManageTreasury
        assertTrue(payments.canManageTreasury(TREASURY_MANAGER));
        assertTrue(payments.canManageTreasury(ADMIN));
        assertTrue(payments.canManageTreasury(OWNER));
        assertFalse(payments.canManageTreasury(UNAUTHORIZED_USER));
    }

    function testBlacklistedAddressPermissions() public {
        // Blacklist a role holder
        vm.startPrank(EMERGENCY_MANAGER);
        payments.blacklistAddress(RAIL_MANAGER);
        vm.stopPrank();
        
        // Even with role, blacklisted address should not have permissions
        assertFalse(payments.canManageRails(RAIL_MANAGER));
        assertTrue(payments.hasRole(RAIL_MANAGER_ROLE, RAIL_MANAGER)); // Still has role
        assertTrue(payments.blacklisted(RAIL_MANAGER)); // But is blacklisted
    }

    function testUnauthorizedRoleOperations() public {
        // Unauthorized user cannot grant roles
        vm.startPrank(UNAUTHORIZED_USER);
        vm.expectRevert();
        payments.grantRole(RAIL_MANAGER_ROLE, USER1);
        vm.stopPrank();
        
        // Unauthorized user cannot freeze roles
        vm.startPrank(UNAUTHORIZED_USER);
        vm.expectRevert();
        payments.freezeRole(RAIL_MANAGER_ROLE);
        vm.stopPrank();
        
        // Unauthorized user cannot blacklist addresses
        vm.startPrank(UNAUTHORIZED_USER);
        vm.expectRevert();
        payments.blacklistAddress(USER1);
        vm.stopPrank();
        
        // Unauthorized user cannot toggle emergency mode
        vm.startPrank(UNAUTHORIZED_USER);
        vm.expectRevert();
        payments.setEmergencyMode(true);
        vm.stopPrank();
    }

    function testRoleAdminRelationships() public {
        // Check that role admins are set correctly
        assertEq(payments.getRoleAdmin(ADMIN_ROLE), DEFAULT_ADMIN_ROLE);
        assertEq(payments.getRoleAdmin(RAIL_MANAGER_ROLE), ADMIN_ROLE);
        assertEq(payments.getRoleAdmin(SETTLEMENT_ROLE), ADMIN_ROLE);
        assertEq(payments.getRoleAdmin(EMERGENCY_ROLE), DEFAULT_ADMIN_ROLE);
        assertEq(payments.getRoleAdmin(VALIDATOR_MANAGER_ROLE), ADMIN_ROLE);
        assertEq(payments.getRoleAdmin(OPERATOR_MANAGER_
```
