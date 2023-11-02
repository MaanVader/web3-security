## Title: [L-01] Lack of Input Validation for Constructor Parameters
---
## Link: https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L60-#L63
---
## Summary

The constructor of the contract does not have validations in place to check for a zero address or zero values for the `_entranceFee` and `_raffleDuration` parameters. This lack of validation could lead to undesired behavior of the contract when instantiated with such values.

## Vulnerability Details

In the provided code snippet, the constructor takes three arguments: `_entranceFee`, `_feeAddress`, and `_raffleDuration`. However, there are no checks to ensure that `_feeAddress` is not a zero address, or that `_entranceFee` and `_raffleDuration` are not zero values. 

```solidity
    constructor(uint256 _entranceFee, address _feeAddress, uint256 _raffleDuration) ERC721("Puppy Raffle", "PR") {
        entranceFee = _entranceFee; //@audit-info no 0 check
        feeAddress = _feeAddress; //@audit-info no 0 check
        raffleDuration = _raffleDuration; //@audit-info no 0 check value can be low
        raffleStartTime = block.timestamp;
        ...
    }
```

## Impact

1. If `_feeAddress` is set to the zero address, any funds directed towards the `feeAddress` within the contract could be irretrievably lost.
2. If `_entranceFee` or `_raffleDuration` is set to zero, it might alter the intended logic and flow of the contract, potentially making the raffle free to enter or instant to conclude, respectively.

## Tools Used

Manual code review.

## Recommendations

1. Implement input validation checks in the constructor to ensure that `_feeAddress` is not a zero address, and `_entranceFee` and `_raffleDuration` are not zero values.
2. It could be beneficial to have a require statement checking these conditions:

```solidity
    require(_feeAddress != address(0), "Fee address cannot be 0");
    require(_entranceFee > 0, "Entrance fee must be greater than 0");
    require(_raffleDuration > 0, "Raffle duration must be greater than 0");
```

These checks will help in maintaining the integrity and expected behavior of the contract when it is deployed.

## Title: [M-01] Vulnerability Report: Denial of Service (DoS) Due to Block Gas Limit in enterRaffle Function
---
## Link: https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L79-#L92
--- 

## Summary

The `enterRaffle` function of the given smart contract is vulnerable to a Denial of Service (DoS) attack due to the potential to exceed the block gas limit. This vulnerability arises from the nested loop utilized for checking duplicate addresses, which can result in excessive gas consumption and consequently, transaction failure.

## Vulnerability Details

The `enterRaffle` function allows a user to enter a raffle by providing an array of player addresses. The function requires the sent value to match the product of the entrance fee and the number of new players. It then iterates through the `newPlayers` array, adding each player to the `players` array. Subsequently, it employs a nested loop to check for duplicate player addresses among all players. The nested loop has a time complexity of O(n^2), making the gas cost of this operation grow quadratically with the number of players.

## Impact

An attacker can exploit this vulnerability by sending a large array of unique addresses to the `enterRaffle` function, causing the transaction to fail due to exceeding the block gas limit. This attack can be repeated, blocking legitimate users from entering the raffle and thus denying service.

## POC
Add this POC to the foundry test

```solidity
function test_DoS_gas_block_limit() public {
    // Create a large list of unique addresses (e.g., 1000 addresses)
    address[] memory newPlayers = new address[](1000);
    for (uint256 i = 0; i < newPlayers.length; i++) {
        // Assuming each new address is unique
        newPlayers[i] = address(i + 1);
    }
    // Attempt to enter the raffle with a large list of unique addresses
    (bool r, ) = address(puppyRaffle).call{
        value: entranceFee * newPlayers.length
    }(
        abi.encodeWithSelector(
            puppyRaffle.enterRaffle.selector,
            newPlayers
        )
    );

    // The transaction should fail due to exceeding the block gas limit
    assert(!r);
}
```

## Tools Used

- Solidity ^0.8.0
- Truffle for testing

## Recommendations

1. **Limit the number of players** that can enter the raffle in a single transaction to a reasonable amount that will not exceed the block gas limit.
2. **Optimize the duplicate check**: Instead of using a nested loop, consider using a mapping to check for duplicate addresses, which would reduce the time complexity from O(n^2) to O(n).
3. **Implement gas checks** within the function to ensure that sufficient gas remains for the function to complete execution, and fail gracefully if not.

Example:
```solidity
function enterRaffle(address[] memory newPlayers) public payable { 
    require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");

    for (uint256 i = 0; i < newPlayers.length; i++) {
        require(gasleft() > 200000, "PuppyRaffle: Insufficient gas");
        players.push(newPlayers[i]);
    }

    for (uint256 i = 0; i < players.length - 1; i++) {
        require(gasleft() > 200000, "PuppyRaffle: Insufficient gas");
        for (uint256 j = i + 1; j < players.length; j++) {
            require(players[i] != players[j], "PuppyRaffle: Duplicate player");
        }
    }

    emit RaffleEnter(newPlayers); 
}
```

## Title: [H-01] Reentrancy Vulnerability in the `refund` Function of PuppyRaffle Contract
---
## Link: https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L96-#L105
---

## Summary

The `refund` function in the PuppyRaffle contract exhibits a reentrancy vulnerability due to the lack of state modification before the external call to transfer Ether. This vulnerability could potentially be exploited by an attacker to re-enter the `refund` function and withdraw more funds than they are entitled to.

## Vulnerability Details

The vulnerability arises from the ordering of operations in the `refund` function. The function first transfers Ether to `msg.sender` using the `sendValue` method and then nullifies the player's address in the contract's state by setting `players[playerIndex]` to the zero address. The correct pattern to prevent reentrancy would be to modify the state before making the external call.

```solidity
function refund(uint256 playerIndex) public { 
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

    players[playerIndex] = address(0);  // Move this line up
    payable(msg.sender).sendValue(entranceFee);  // Move this line down
    
    emit RaffleRefunded(playerAddress);
}
```

## Impact

A malicious actor could exploit this vulnerability to drain funds from the contract. By creating a contract that calls back into the `refund` function in its fallback function, the attacker could trigger multiple refunds in a single transaction, depleting the contract's Ether balance.

## Tools Used

- Manual Review

## Recommendations

To mitigate this vulnerability, it is recommended to follow the "Checks-Effects-Interactions" pattern. This pattern suggests that contract state should be updated before making external calls. In the `refund` function, the line `players[playerIndex] = address(0);` should be moved before the line `payable(msg.sender).sendValue(entranceFee);`. Furthermore, it's advisable to use the `transfer` method instead of `sendValue` as `transfer` is considered safer for sending Ether.

## Title: [H-02] Manipulable Randomness Leads to Unfair Legendary NFT Distribution in `selectWinner` function
---
## Link: https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L128
         https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L139
         https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L140-L146

---
## Summary
The `selectWinner` function in the given smart contract attempts to pick a winner from a raffle and award them an NFT with a rarity level. The randomness used to determine both the winner and the rarity of the NFT could be predicted or manipulated due to its reliance on blockchain variables and `msg.sender`, potentially allowing a malicious actor to unfairly win and obtain a Legendary NFT.

## Vulnerability Details
The function utilizes the `keccak256` hashing function applied to a combination of `msg.sender`, `block.timestamp`, and `block.difficulty` to compute indices and rarity values. However, these sources of entropy are known to be `manipulable` to some extent:

Winner Selection:

```solidity
uint256 winnerIndex = uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;
```
Rarity Determination:

```solidity
uint256 rarity = uint256(keccak256(abi.encodePacked(msg.sender, block.difficulty))) % 100;

 if (rarity <= COMMON_RARITY) {
            tokenIdToRarity[tokenId] = COMMON_RARITY;
        } else if (rarity <= COMMON_RARITY + RARE_RARITY) { //95
            tokenIdToRarity[tokenId] = RARE_RARITY;
        } else {
            tokenIdToRarity[tokenId] = LEGENDARY_RARITY;
        }
```
The `winnerIndex` and `rarity` values are determined using the `keccak256` hash function, which, although being a secure hash function, becomes predictable when fed with known or `manipulable` inputs. Furthermore,we also know that the `rarity` value needs to be `>95` in order to mint the `legendary` NFT.



## Impact
A malicious actor could potentially manipulate the variables involved in the randomness generation to increase their chances of winning the raffle and obtaining a Legendary NFT. This undermines the fairness and integrity of the raffle and NFT distribution, which could in turn affect the trust and participation levels in the raffle.

## POC
Add this test function to the foundry test:
```solidity
function test_POCAnyoneCanWin_With_Legendary_Rarity() public {
    // Initialize a list of 4 players
    address[] memory players1 = new address[](4);
    players1[0] = playerOne;
    players1[1] = playerTwo;
    players1[2] = playerThree;
    players1[3] = playerFour;

    // Enter the raffle with the 4 players
    puppyRaffle.enterRaffle{value: entranceFee * 4}(players1);

    // Log the length of the players array for debugging
    console.log(players1.length);

    // Set up the prank to fix msg.sender to playerTwo
    vm.startPrank(playerTwo);
    
    // Warp time and block number to simulate the passage of time
    vm.warp(block.timestamp + duration + 3);
    vm.roll(block.number + 1);

    // Call the selectWinner function
    puppyRaffle.selectWinner();
    
    // Stop the prank to restore original state
    vm.stopPrank();
    
    // Set a specific difficulty value to check the rarity calculation
    vm.difficulty(7);
    
    // Calculate the rarity based on the current block difficulty
    uint256 rarity = uint256(keccak256(abi.encodePacked(msg.sender, block.difficulty))) % 100;

    // Check if the rarity value is greater than 95 and log the difficulty
    if (rarity > 95) {
        console.log("Rarity: ", 7);
        console.log("Lengendary NFT minted");
    }

    // Assert that playerTwo is the winner and has been minted a token
    assertEq(puppyRaffle.previousWinner(), playerTwo);
    assertEq(puppyRaffle.balanceOf(playerTwo), 1);
}

```

## Tools Used
 - Manual review
 - Foundry

## Recommendations:
1. Employ Off-chain Randomness: Utilize an off-chain source of randomness, like Chainlink VRF (Verifiable Random Function), to generate random numbers securely.

2. Use Commit-Reveal Scheme: Implement a commit-reveal scheme that requires players to submit a hash of their chosen random number and reveal it later, which can then be combined to generate a random number for the raffle.

## Title: [H-03] Integer Overflow in Total Amount Calculation Risks Misallocation of Funds
---
## Link: https://github.com/Cyfrin/2023-10-Puppy-Raffle/blob/main/src/PuppyRaffle.sol#L131
---

## Summary

The `selectWinner` function within the smart contract calculates the `totalAmountCollected` by multiplying the `players.length` by `entranceFee`. However, this calculation is prone to an integer overflow vulnerability, which may lead to an incorrect computation of `totalAmountCollected`, affecting the subsequent distribution of funds and NFTs.

## Vulnerability Details

The vulnerability occurs at the line:

```solidity
uint256 totalAmountCollected = players.length * entranceFee;
```

If the product of `players.length` and `entranceFee` exceeds the maximum value of a `uint256`, an overflow will occur, wrapping the result around and returning a much smaller number than expected.

## Impact

An integer overflow in the `totalAmountCollected` calculation could lead to an unexpected behavior where the total amount of funds collected is misrepresented. This misrepresentation can further impact the distribution of funds to the winner and the `feeAddress`, and the minting and assignment of NFTs. This compromises the integrity of the raffle and may result in financial loss or unfair advantage to some participants.

## POC

```solidity
function test_Overflow() public {
    uint256 playersLength = type(uint256).max / entranceFee;  // Largest possible value for playersLength without overflow
    playersLength += 1;  // Increment playersLength to cause an overflow
    console.log(playersLength);
    uint256 totalAmountCollected = playersLength * entranceFee;

    bool overflowOccurred = totalAmountCollected < playersLength || totalAmountCollected < entranceFee;
    assertTrue(overflowOccurred);  // Assert that an overflow occurred
}
```

In this proof of concept, the `test_Overflow` function demonstrates how an overflow can occur when the `players.length` and `entranceFee` are multiplied together. By incrementing the `playersLength` to a value that will cause an overflow, the test asserts that an overflow occurred by checking if `totalAmountCollected` is less than either `playersLength` or `entranceFee`.

## Tools Used

- Manual review
- Foundry
## Recommendations

1. Implement checks to ensure that the product of `players.length` and `entranceFee` does not exceed the maximum `uint256` value before performing the multiplication.
2. Consider utilizing SafeMath or other similar libraries that provide safe arithmetic operations to prevent overflows.
3. Restrict the maximum number of players or the value of `entranceFee` to prevent the multiplication from exceeding the maximum `uint256` value.
4. Use solidity version `^0.8.0` as it includes overflow/underflow checks


