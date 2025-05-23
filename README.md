# memo-did

A golang package to work with memo DIDs

## Specifications

- [Decentralized Identifiers](https://w3c.github.io/did-core/)
- [MEMO DID](https://github.com/memoio/did-docs/blob/master/memo-did-design.md)

## Example

### 1.Create

Create/Register DID needs to interactive with memo chain.

```go
package main

import (
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	memodid "github.com/memoio/memo-did"
)

func main() {
	privateKey, err := crypto.HexToECDSA("86278d5ea0c4f357ba6bb6eedfeb4aee3f35650eb45ab4b21fa2e9e9f89fe8c")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	controller, err := memodid.NewMemoDIDController(privateKey, "dev")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	err = controller.RegisterDID()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
}
```

### 2.Update

Update the DID document, mainly for the controller attribute, verificationMethod attribute, authentication attribute, assertionMethod attribute, capabilityDelegation attribute and recovery attribute in the DID document. You can view the [interface file](./didstore.go) for a detailed interface description.

```go
// Get the controller from step 1
did := controller.DID()
controllerDID := memodid.ParseMemoDID("did:memo:b49ca7589e68b79190afdee67da56d7610a0407d54750f85749b5d90b7c7676f#masterKey")

// Add 'controllerDID' to the controller attribute of 'did'
err := controller.AddController(did, controllerDID)
if err != nil {
    fmt.Println(err.Error())
    return
}
```

### 3.Delete

Deleting a DID and DID documents is irreversible and the corresponding DID is permanently invalid.

```go
// Get the controller from step 1
did := controller.DID()

err := controller.DeactivateDID(did)
if err != nil {
    fmt.Println(err.Error())
    return
}
```

### 4.Resolve

Parsing DID will parse the complete DID document based on the DID string.

```go
// Get the controller from step 1
did := controller.DID()

resolver, err := memodid.NewMemoDIDResolver("dev")
if err != nil {
	fmt.Println(err.Error())
    return
}

document, err := resolver.Resolve("did:memo:797fa97627bb970c77e7a7c9ada05626fbeb7378a295603f2b61d1947f0e6f93")
if err != nil {
    fmt.Println(err.Error())
    return
}
document, err = resolver.Resolve(did.String())
if err != nil {
	fmt.Println(err.Error())
    return
}

data, err := json.MarshalIndent(document, "", "\t")
if err != nil {
    fmt.Println(err.Error())
    return
}

fmt.Println(string(data))
```

### 5.Dereference

Dereference the VerificationMethod ID to obtain the public key and verification method type.

```go
// Get the controller from step 1
did := controller.DID()

vtype, publicKey, err := resolver.Resolve(document.Authentication[0].String())
if err != nil {
    fmt.Println(err.Error())
    return
}
vtype, publicKey, err = resolver.Resolve("did:memo:797fa97627bb970c77e7a7c9ada05626fbeb7378a295603f2b61d1947f0e6f93#masterKey")
if err != nil {
    fmt.Println(err.Error())
    return
}
```

## Test

Run the following command to test.

```bash
go test -v
```
