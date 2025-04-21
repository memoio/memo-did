# memo-did

A golang package to work with memo DIDs

## Specifications

- [Decentralized Identifiers](https://w3c.github.io/did-core/)
- [MEMO DID](https://github.com/memoio/did-docs/blob/master/memo-did-design.md)

## Example

### 1.Create

创建/注册DID需要和memo链进行交互，因此需要

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

更新DID文档，主要是针对DID文档中的controller属性，verificationMethod属性，authentication属性，assertionMethod属性，capabilityDelegation属性以及recovery属性进行更新。可以查看[接口文件](./didstore.go)查看详细的接口描述。

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

删除DID以及DID文档，删除不可恢复且对应的DID永久无效。

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

解析DID会根据DID字符串解析出完整的DID文档。

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

解引用通过VerificationMethod的ID解析得到公钥以及验证方法类型。

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

运行下列命令测试

```bash
go test -v
```

