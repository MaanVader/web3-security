## Title: [H-01] Sensitive Data Exposure Due to Misunderstanding of Blockchain Transparency

### Github links:
* https://github.com/Cyfrin/2023-10-PasswordStore/blob/main/src/PasswordStore.sol#L14

---

## Summary

The `PasswordStore` contract within the provided codebase is intended to securely hold a password for the contract owner. However, due to the transparent nature of blockchain technology, the `private` visibility specifier doesn't provide the expected level of data privacy. Despite the restrictions placed within the contract's functions, the value of the password stored in the `s_password` variable is publicly visible to anyone inspecting the blockchain's state.

---

## Vulnerability Details

The contract utilizes a `private` variable `s_password` to store a password and restricts access to this password through the `getPassword` function, only allowing the contract owner to retrieve it. However, this mechanism is flawed due to the transparent nature of blockchain data. All data, including that marked as `private`, is visible to any party with access to the blockchain's state data. Additionally, the `setPassword` function emits an event `SetNetPassword` whenever the password is changed, which, while not leaking the password itself, could leak the timing of password changes.

### Code Snippet:

```solidity
string private s_password;  // This private variable is not actually private due to blockchain transparency.

...

function setPassword(string memory newPassword) external { 
    s_password = newPassword;
    emit SetNetPassword();  // This event can leak the timing of password changes.
}

...

function getPassword() external view returns (string memory) {
    ...
    return s_password;  // Only the owner can call this, but anyone can view s_password by inspecting the blockchain.
}
```

---

## Impact

The impact of this vulnerability is high. The contract owner's password is exposed to the public, leading to a complete loss of confidentiality. This exposure could potentially lead to unauthorized access or other malicious activities if the password is reused elsewhere.

---

## Tools Used

- Manual Code Review

---

## Recommendations

- It is highly advised not to store sensitive information such as passwords on-chain. Blockchain's transparency makes it unsuitable for holding confidential data.
- If authentication is necessary, consider implementing off-chain solutions or using cryptographic proofs, like signatures, to verify identities.
- Replace the password storage and retrieval system with a more secure, off-chain solution to ensure the confidentiality and integrity of sensitive data.

---

## Title: [H-02] Unauthorized Password Alteration due to Missing Access Control in `setPassword` Function

### Github links:
* https://github.com/Cyfrin/2023-10-PasswordStore/blob/main/src/PasswordStore.sol#L26-#L29

---

## Summary

The `PasswordStore` contract is designed to securely store a password while allowing only the contract owner to modify it. However, a critical flaw in the `setPassword` function permits any user to change the stored password, severely compromising the contract's integrity and security.

---

## Vulnerability Details

The `setPassword` function is intended to be restricted for use by the contract owner only. Nevertheless, the function lacks any access control mechanisms, such as the commonly used `onlyOwner` modifier, to enforce this restriction. Consequently, any malicious actor can call this function to change the password to a value of their choosing.

### Code Snippet:

```solidity
function setPassword(string memory newPassword) external { 
    s_password = newPassword;
    emit SetNetPassword();
}
```

---

## Impact

This vulnerability carries a high severity rating. Unauthorized users can change the password, potentially leading to unauthorized access or other malicious activities, if the password is used for critical operations within or outside the blockchain environment.

---

## POC (Proof of Concept)

```solidity
function test_anyone_can_set_password() public{
    vm.startPrank(address(2));
    string memory new_passwd = "weeeeeee";
    passwordStore.setPassword(new_passwd);
    vm.stopPrank();
    vm.startPrank(owner);
    string memory get_passwd = passwordStore.getPassword();
    //console.log(get_passwd);
    assertEq(new_passwd,get_passwd);
}
```
Add the POC function above to the `PasswordStore.t.sol` file

Output:
```
Running 1 test for test/PasswordStore.t.sol:PasswordStoreTest
[PASS] test_anyone_can_set_password() (gas: 22887)
Traces:
  [22887] PasswordStoreTest::test_anyone_can_set_password()
    ├─ [0] VM::startPrank(0x0000000000000000000000000000000000000002)
    │   └─ ← ()
    ├─ [6686] PasswordStore::setPassword(weeeeeee)
    │   ├─ emit SetNetPassword()
    │   └─ ← ()
    ├─ [0] VM::stopPrank()
    │   └─ ← ()
    ├─ [0] VM::startPrank(0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38)
    │   └─ ← ()
    ├─ [3320] PasswordStore::getPassword() [staticcall]
    │   └─ ← weeeeeee
    └─ ← ()
```

we an see that the password has changed.

---

## Tools Used

- Foundry 
- Manual Review 

---

## Recommendations

- Implement the `onlyOwner` modifier on the `setPassword` function to ensure that only the contract owner can change the password. The `onlyOwner` modifier should verify that `msg.sender` is equal to the `s_owner` before proceeding with the function execution.

```solidity
modifier onlyOwner() {
    require(msg.sender == s_owner, "Not authorized");
    _;
}

function setPassword(string memory newPassword) external onlyOwner { 
    s_password = newPassword;
    emit SetNetPassword();
}
```


---


## Title: [L-01] Enhancement of Owner Address Immutability in PasswordStore Contract

### Github links:
* https://github.com/Cyfrin/2023-10-PasswordStore/blob/main/src/PasswordStore.sol#L13

---


## Summary

The `PasswordStore` contract in the given Solidity code is designed to allow a user to store and update a password. The owner of the contract is assigned during contract deployment. However, the `s_owner` variable is defined as private but not immutable, which, although doesn't pose a security threat, goes against the optimization and clarity best practices.

---

## Vulnerability Details

In the given contract, the `s_owner` variable is defined as `address private s_owner;`. However, since the owner address is set at the time of contract deployment and is not meant to be changed afterward, it is a good practice to declare the `s_owner` variable as immutable. Immutable variables can also help save gas as they allow for certain optimizations by the Solidity compiler.

---

## Impact

The impact of this issue is low. It doesn't pose a security risk but missing out on declaring `s_owner` as immutable might lead to slight gas inefficiencies during contract execution. Additionally, not adhering to this best practice can potentially cause confusion or errors in more complex contracts or if the contract undergoes future development.

---

## Tools Used

Manual Code Review

---

## Recommendations

It's recommended to change the declaration of `s_owner` from:
```solidity
address private s_owner;
```
to:
```solidity
address private immutable s_owner;
```
This change reflects the intent that the owner address is set at contract deployment and should not change afterward, and allows the Solidity compiler to apply optimizations that can save gas. Making this change will align the contract with Solidity best practices for state variable immutability.

---

## Title: [L-02] Inaccurate Comment in `getPassword` Function of PasswordStore Contract

### Github links:
* https://github.com/Cyfrin/2023-10-PasswordStore/blob/main/src/PasswordStore.sol#L33

---

## Summary

The `getPassword` function in the provided `PasswordStore` contract has a comment that inaccurately mentions a parameter `newPassword`. However, the function signature does not include this parameter. This discrepancy could lead to confusion for developers or auditors reviewing the code.

---

## Vulnerability Details

In the comment preceding the `getPassword` function, there's a mention of a parameter `newPassword` in the `@param` tag. However, the function `getPassword` does not take any parameters as per its definition. This inaccurate documentation may mislead someone reviewing the contract into thinking there's a missing parameter or some other issue with the function signature.

```solidity
/*
 * @notice This allows only the owner to retrieve the password.
 * @param newPassword The new password to set.
 */
function getPassword() external view returns (string memory) {
    if (msg.sender != s_owner) {
        revert PasswordStore__NotOwner();
    }
    return s_password;
}
```

---

## Impact

The impact of this issue is low. It does not have any effect on the contract's functionality or security. However, accurate and clear comments are crucial for understanding the contract, especially for those who might interact with or audit the contract in the future. Misleading comments can cause confusion and potentially lead to misunderstandings about how the contract functions.

---

## Tools Used

Manual Code Review

---

## Recommendations

It's recommended to correct the comment to accurately reflect the function's behavior and remove the incorrect `@param` tag. The corrected comment might look something like:
