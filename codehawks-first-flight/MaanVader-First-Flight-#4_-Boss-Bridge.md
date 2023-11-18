# First Flight #4: Boss Bridge - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)
- ## High Risk Findings
    - ### [H-01. nrestricted Access and Unauthorized Transfers in `L1BossBridge's` `depositTokensToL2` Function](#H-01)
- ## Medium Risk Findings
    - ### [M-01. Contract Deployment Vulnerability in zkSync L2 Environment](#M-01)
    - ### [M-02. Centralized risk of Ownership](#M-02)



# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #4

### Dates: Nov 9th, 2023 - Nov 15th, 2023

[See more contest details here](https://www.codehawks.com/contests/clomptuvr0001ie09bzfp4nqw)

# <a id='results-summary'></a>Results Summary

### Number of findings:
   - High: 1
   - Medium: 2
   - Low: 0


# High Risk Findings

## <a id='H-01'></a>H-01. nrestricted Access and Unauthorized Transfers in `L1BossBridge's` `depositTokensToL2` Function            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-11-Boss-Bridge/blob/main/src/L1BossBridge.sol#L70-L78

## Summary
A critical security vulnerability has been identified in the `depositTokensToL`2 function of the `L1BossBridge` smart contract. This function currently allows any user to initiate a token deposit on behalf of any other address without requiring proper authorization. This flaw can be exploited by malicious actors to transfer tokens from any address to their own account on Layer 2 (L2), potentially leading to unauthorized token transfers and financial loss for affected users.

## Vulnerability Details
The function lacks necessary checks to confirm that the caller (msg.sender) has the authority to move tokens from the `from` address. This oversight allows an attacker to use the depositTokensToL2 function to deposit tokens from any user's address into an L2 address of their choice, without the token owner's consent.

## Impact
* Unauthorized Token Transfers: This vulnerability allows attackers to redirect token deposits to their own L2 addresses, effectively stealing tokens from other users.
* Loss of User Trust: Such vulnerabilities can significantly undermine the credibility and security perception of the token bridge, causing potential long-term damage to user trust.
* Financial Risks: Users are at risk of financial losses due to unauthorized token movements.

## Tools Used
- Manual Review
- Foundry

## Recommendations
To mitigate this vulnerability, the depositTokensToL2 function should be modified to include a check ensuring that the caller is authorized to use tokens from the from address. This can be implemented as follows:

```solidity
function depositTokensToL2(address from, address l2Recipient, uint256 amount) external whenNotPaused { 
    require(msg.sender == from, "Unauthorized: Caller must be token owner");

    if (token.balanceOf(address(vault)) + amount > DEPOSIT_LIMIT) {
        revert L1BossBridge__DepositLimitReached();
    }
    token.safeTransferFrom(from, address(vault), amount);

    emit Deposit(from, l2Recipient, amount); 
}


```
		
# Medium Risk Findings

## <a id='M-01'></a>M-01. Contract Deployment Vulnerability in zkSync L2 Environment            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-11-Boss-Bridge/blob/main/src/TokenFactory.sol#23-L29

Contract Deployment Vulnerability in zkSync L2 Environment

##Summary
The `deployToken` function, designed for contract deployment on zkSync L2, has been identified with a critical incompatibility issue. This stems from zkSync's unique contract deployment requirements, which are not met by the current implementation.

## Vulnerability Analysis

#### Function Mechanism:
- The function dynamically deploys contracts using provided bytecode at runtime. However, zkSync's compiler requires knowing the full bytecode at compile time for correct operation.

#### zkSync Deployment Requirements:
- zkSync utilizes the hash of contract bytecode for deployment, contrasting with Ethereum's model. This requirement ensures that the bytecode of all deployable contracts is known before deployment, which is not the case in the `deployToken` function.

#### Potential Consequences:
- **Deployment Failure**: Any attempt to deploy contracts through this function on zkSync will result in failure, as the bytecode is not pre-known to the compiler.
- **Operational Breakdown**: The factory pattern used in `deployToken` is ineffective under zkSync's architecture, leading to a breakdown in the intended functionality of the contract.

### Recommendations for Remediation

#### Code Restructuring:
- Refactor `deployToken` to include the bytecode of deployable contracts within the contract. This ensures the compiler knows the bytecode in advance.

```solidity
// Example of static bytecode inclusion
bytes memory staticBytecode = ...; // Bytecode of the contract to be deployed
```

#### Compatibility Review:
- Perform a comprehensive compatibility review to ensure all aspects of the contract align with zkSync's unique operational model.

### Conclusion
To ensure successful deployment and functionality on zkSync L2, significant modifications to the `deployToken` function are required. Adapting to zkSync's deployment method is essential for the contract's effective operation in this environment.
## <a id='M-02'></a>M-02. Centralized risk of Ownership            

### Relevant GitHub Links
	
https://github.com/Cyfrin/2023-11-Boss-Bridge/blob/main/src/TokenFactory.sol#L23

https://github.com/Cyfrin/2023-11-Boss-Bridge/blob/main/src/L1BossBridge.sol#L49-L60

https://github.com/Cyfrin/2023-11-Boss-Bridge/blob/main/src/L1Vault.sol#L19

## Summary
The  smart contract exhibits a significant risk due to its centralized ownership model. A Proof of Concept (PoC) demonstrates how the compromise of the owner's private key can lead to complete control of the contract by an attacker. This vulnerability can have severe implications, including the unauthorized pausing of the bridge and alteration of critical contract parameters.

## Vulnerability Details
The contract is vulnerable to owner key compromise as it is not using a multi-sig wallet. If the owner's private key is obtained by an attacker, they gain full control over the contract's functions. This is because a lot of the functions are under the owners control

## POC
Add this test to `L1TokenBridge.t.sol`:

```solidity
 function testRiskWithCompromisedOwnerKey() public { 
        // Step 1: Verify the current owner
        address currentOwner = tokenBridge.owner();
        assertEq(currentOwner, deployer, "Deployer should be the initial owner");

        address attacker = makeAddr("attacker");

        // Step 2: Simulate ownership compromise
        // Transfer ownership to the attacker (simulate a compromised key scenario)
        vm.prank(currentOwner);
        tokenBridge.transferOwnership(attacker);

        // Verify that the attacker is now the owner
        assertEq(tokenBridge.owner(), attacker, "Attacker should be the new owner");

        // Step 3: Attacker actions as the new owner
        vm.startPrank(attacker);

        // Example action: Pausing the bridge
        tokenBridge.pause();
        assertTrue(tokenBridge.paused(), "Bridge should be paused by the attacker");

        // Additional malicious action: Adding a fake signer
        address fakeSigner = makeAddr("fakeSigner");
        tokenBridge.setSigner(fakeSigner, true);
        assertTrue(tokenBridge.signers(fakeSigner), "Fake signer should be added by the attacker");

        vm.stopPrank();

        // Step 4: Check the impact on normal users
        vm.startPrank(user);
        uint256 depositAmount = 10e18;
        token.approve(address(tokenBridge), depositAmount);

        // Expect that the deposit will fail because the bridge is paused
        vm.expectRevert(Pausable.EnforcedPause.selector);
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);

        vm.stopPrank();
    }

```

The test above simulates a successfull private key compromise of the owner.

## Impact
Total Control by Attacker: An attacker with the owner's key can unilaterally make critical decisions, including pausing the bridge or changing signer permissions.
Disruption of Service: Users may experience disruption in services, such as deposit and withdrawal functions, leading to potential financial losses and loss of trust.
Manipulation of Contract Parameters: The attacker can manipulate signers, potentially leading to broader security breaches within the system.

## Tools Used
- Manual Review
- Foundry

## Recommendations
Enhance Ownership Model:
Implement a multi-signature mechanism for critical functions, requiring multiple parties to agree on significant changes.
Introduce time locks for sensitive actions, allowing users to react in case of suspicious activities.




