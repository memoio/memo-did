package memodid

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/xerrors"
)

var globalPrivateKey1 string = "f9729aef404b8c13d06cf888376b04fd17581b9c308f9b4b16c020736ae89cd4"
var globalPrivateKey2 string = "4bb551355d8eb5b22c28380e215a9d224b82f52f56c0f448e1b4e2f0a0053707"
var globalPrivateKey3 string = "593b0434faac6e71a8d55545a56653d3f0cbe309b174735ec09d7a4ac05ff75f"
var globalPrivateKey4 string = "2e28ffc9bdb08ae17b98f39666aac237b6e277873f12718dbc8441ea546e603d"
var globalPrivateKey5 string = "c7983265caddf784f26d6165cb01100176840097336f37a99038d918c2ca820d"

// var address1 string = "0xe89971bfeEA7381d47fE608d676dfb5440F0fD2E"
// var address2 string = "0x7C0491aE63e3816F96B777340b1571feA7bB21dE"
// var address3 string = "0xc0FF8898729d543c197Fb8b8ef7EE2f39024e1e8"
// var address4 string = "0x53F76F77DeC24D601ad3001114C9a35EfD4A5F5F"
// var address5 string = "0xC44F1bccDb80F266b727c5B3f2839AA3a2FEf1d1"

func ToPublicKey(privateKeyHex string) (string, error) {
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return "", err
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", xerrors.Errorf("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	return hex.EncodeToString(crypto.CompressPubkey(publicKeyECDSA)), nil
}

func ToPublicKeys(privateKeyHex []string) ([]*ecdsa.PrivateKey, []string, error) {
	var sks []*ecdsa.PrivateKey
	var pks []string
	for _, sk := range privateKeyHex {
		publicKey, err := ToPublicKey(sk)
		if err != nil {
			return nil, nil, err
		}

		privateKey, err := crypto.HexToECDSA(sk)
		if err != nil {
			return nil, nil, err
		}

		sks = append(sks, privateKey)
		pks = append(pks, publicKey)
	}

	return sks, pks, nil
}

func genVerificationMethod(did *MemoDID, methodIndex int64, controller *MemoDID, vtype, publicKeyHex string) (VerificationMethod, error) {
	if controller == nil {
		controller, _ = ParseMemoDID("did:memo:0000000000000000000000000000000000000000000000000000000000000000")
	}

	didUrl, err := did.DIDUrl(methodIndex)
	if err != nil {
		return VerificationMethod{}, err
	}

	if publicKeyHex[:2] != "0x" {
		publicKeyHex = "0x" + publicKeyHex
	}

	return VerificationMethod{
		ID:           *didUrl,
		Controller:   *controller,
		Type:         vtype,
		PublicKeyHex: publicKeyHex,
	}, nil
}

func TestRegisterDID(t *testing.T) {
	privateKey, err := crypto.HexToECDSA(globalPrivateKey1)
	if err != nil {
		t.Error(err.Error())
		return
	}

	publicKeyHex, err := ToPublicKey(globalPrivateKey1)
	if err != nil {
		t.Error(err.Error())
		return
	}

	// publicKeyHex2, err := ToPublicKey("4bb551355d8eb5b22c28380e215a9d224b82f52f56c0f448e1b4e2f0a0053707")
	// if err != nil {
	// 	t.Error(err.Error())
	// 	return
	// }

	controller, err := NewMemoDIDController(privateKey, "dev")
	if err != nil {
		t.Error(err.Error())
		return
	}
	resolver, err := NewMemoDIDResolver("dev")
	if err != nil {
		t.Error(err.Error())
		return
	}

	err = controller.RegisterDID()
	if err != nil {
		t.Error(err.Error())
		return
	}

	t.Log("resolving " + controller.DID().String())
	document, err := resolver.Resolve(controller.DID().String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	verificationMethod, err := genVerificationMethod(controller.DID(), 0, nil, "EcdsaSecp256k1VerificationKey2019", publicKeyHex)
	if err != nil {
		t.Error(err.Error())
		return
	}

	d := &MemoDIDDocument{
		Context:            DefaultContext,
		ID:                 *controller.DID(),
		VerificationMethod: []VerificationMethod{verificationMethod},
	}

	// document, err := genNewDocument(did, methodType, publicKeyHex)

	if !reflect.DeepEqual(document, d) {
		t.Error("Unexpect RegisterDID result")
		return
	}

	data, err := json.MarshalIndent(document, "", "\t")
	if err != nil {
		t.Error(err.Error())
		return
	}

	t.Log(string(data))
}

// test creat, read, update and delete
func TestBasic(t *testing.T) {
	sks, pks, err := ToPublicKeys([]string{globalPrivateKey1, globalPrivateKey2, globalPrivateKey3, globalPrivateKey4})
	if err != nil {
		t.Error(err.Error())
		return
	}

	privateKey := sks[0]

	masterKey := pks[0]
	pk1 := pks[1]
	pk2 := pks[2]
	// pk3 := pks[3]

	d := &MemoDIDDocument{}

	controller, err := NewMemoDIDController(privateKey, "dev")
	if err != nil {
		t.Error(err.Error())
		return
	}
	did := controller.DID()
	resolver, err := NewMemoDIDResolver("dev")
	if err != nil {
		t.Error(err.Error())
		return
	}

	// register did(masterKey)
	err = controller.RegisterDID()
	if err != nil {
		t.Error(err.Error())
		return
	}

	document, err := resolver.Resolve(did.String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	verificationMethod, err := genVerificationMethod(did, 0, nil, "EcdsaSecp256k1VerificationKey2019", masterKey)
	if err != nil {
		t.Error(err.Error())
		return
	}

	d.Context = DefaultContext
	d.ID = *did
	d.VerificationMethod = append(d.VerificationMethod, verificationMethod)
	if !reflect.DeepEqual(document, d) {
		t.Error("Unexpect RegisterDID result")
		return
	}

	//
	// add verification method(key-1)
	err = controller.AddVerificationMethod(*did, "EcdsaSecp256k1VerificationKey2019", *did, pk1)
	if err != nil {
		t.Error(err.Error())
		return
	}

	document, err = resolver.Resolve(did.String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	verificationMethod, err = genVerificationMethod(did, 1, did, "EcdsaSecp256k1VerificationKey2019", pk1)
	if err != nil {
		t.Error(err.Error())
		return
	}
	d.VerificationMethod = append(d.VerificationMethod, verificationMethod)
	if !reflect.DeepEqual(document, d) {
		t.Error("Unexpect RegisterDID result")
		return
	}

	//
	// add authentication(key-1)
	err = controller.AddRelationShip(*did, Authentication, document.VerificationMethod[1].ID, 0)
	if err != nil {
		t.Error(err.Error())
		return
	}

	document, err = resolver.Resolve(did.String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	d.Authentication = append(d.Authentication, d.VerificationMethod[1].ID)
	if !reflect.DeepEqual(document, d) {
		t.Error("Unexpect RegisterDID result")
		return
	}

	// data, _ := json.MarshalIndent(document, " ", "\t")
	// t.Log(string(data))
	// data, _ = json.MarshalIndent(d, " ", "\t")
	// t.Log(string(data))

	//
	// add verification method(key-2)
	err = controller.AddVerificationMethod(*did, "EcdsaSecp256k1VerificationKey2019", *did, pk2)
	if err != nil {
		t.Error(err.Error())
		return
	}

	document, err = resolver.Resolve(did.String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	verificationMethod, err = genVerificationMethod(did, 2, did, "EcdsaSecp256k1VerificationKey2019", pk2)
	if err != nil {
		t.Error(err.Error())
		return
	}
	d.VerificationMethod = append(d.VerificationMethod, verificationMethod)
	if !reflect.DeepEqual(document, d) {
		t.Error("Unexpect result")
		return
	}

	//
	// add assertion method(masterKey)
	err = controller.AddRelationShip(*did, AssertionMethod, document.VerificationMethod[0].ID, 0)
	if err != nil {
		t.Error(err.Error())
		return
	}

	document, err = resolver.Resolve(did.String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	d.AssertionMethod = append(d.AssertionMethod, d.VerificationMethod[0].ID)
	if !reflect.DeepEqual(document, d) {
		t.Error("Unexpect result")
		return
	}

	//
	// add delegation(key-1, key-2)
	err = controller.AddRelationShip(*did, CapabilityDelegation, document.VerificationMethod[1].ID, time.Now().Add(7*24*time.Hour).Unix())
	if err != nil {
		t.Error(err.Error())
		return
	}

	err = controller.AddRelationShip(*did, CapabilityDelegation, document.VerificationMethod[2].ID, time.Now().Add(1*time.Minute).Unix())
	if err != nil {
		t.Error(err.Error())
		return
	}

	document, err = resolver.Resolve(did.String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	d.CapabilityDelegation = append(d.CapabilityDelegation, d.VerificationMethod[1].ID)
	d.CapabilityDelegation = append(d.CapabilityDelegation, d.VerificationMethod[2].ID)
	if !reflect.DeepEqual(document, d) {
		t.Error("Unexpect result")
		return
	}

	//
	// add recovery(masterKey, key-1, key-2)
	err = controller.AddRelationShip(*did, Recovery, document.VerificationMethod[0].ID, 0)
	if err != nil {
		t.Error(err.Error())
		return
	}

	err = controller.AddRelationShip(*did, Recovery, document.VerificationMethod[1].ID, 0)
	if err != nil {
		t.Error(err.Error())
		return
	}

	err = controller.AddRelationShip(*did, Recovery, document.VerificationMethod[2].ID, 0)
	if err != nil {
		t.Error(err.Error())
		return
	}

	document, err = resolver.Resolve(did.String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	d.Recovery = append(d.Recovery, d.VerificationMethod[0].ID)
	d.Recovery = append(d.Recovery, d.VerificationMethod[1].ID)
	d.Recovery = append(d.Recovery, d.VerificationMethod[2].ID)

	if !reflect.DeepEqual(document, d) {
		t.Error("Unexpect result")
		return
	}

	//
	// delegation(key-2) expires automatically
	time.Sleep(time.Minute)

	document, err = resolver.Resolve(did.String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	for i, delegation := range d.CapabilityDelegation {
		if delegation.String() == d.VerificationMethod[2].ID.String() {
			d.CapabilityDelegation = append(d.CapabilityDelegation[:i], d.CapabilityDelegation[i+1:]...)
			break
		}
	}
	if !reflect.DeepEqual(document, d) {
		t.Error("Unexpect result")
		return
	}

	// deactivate recovery(key-1)
	err = controller.DeactivateRelationShip(*did, Recovery, document.VerificationMethod[1].ID)
	if err != nil {
		t.Error(err.Error())
		return
	}

	document, err = resolver.Resolve(did.String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	for i, recovery := range d.Recovery {
		if recovery.String() == d.VerificationMethod[1].ID.String() {
			d.Recovery = append(d.Recovery[:i], d.Recovery[i+1:]...)
			break
		}
	}
	if !reflect.DeepEqual(document, d) {
		t.Error("Unexpect result")
		return
	}

	//
	// dactivate verification method(key-2), also dactivate recovery(key-2).
	err = controller.DeactivateVerificationMethod(document.VerificationMethod[2].ID)
	if err != nil {
		t.Error(err.Error())
		return
	}

	document, err = resolver.Resolve(did.String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	d.VerificationMethod = d.VerificationMethod[:2]
	d.Recovery = d.Recovery[:1]
	if !reflect.DeepEqual(document, d) {
		t.Error("Unexpect result")
		return
	}

	data, _ := json.MarshalIndent(document, " ", "\t")
	t.Log(string(data))
	data, _ = json.MarshalIndent(d, " ", "\t")
	t.Log(string(data))

	remainUrl := d.Recovery[0]

	//
	// dactivate did
	err = controller.DeactivateDID(*did)
	if err != nil {
		t.Error(err.Error())
		return
	}

	document, err = resolver.Resolve(did.String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	d = &MemoDIDDocument{}
	if !reflect.DeepEqual(document, d) {
		t.Error("Unexpect result")
		return
	}

	//
	// Trying to update dactivated did
	err = controller.AddVerificationMethod(*did, "EcdsaSecp256k1VerificationKey2019", *did, pk1)
	if err == nil {
		t.Error("There should report an error when trying to update dactivated did")
		return
	}

	err = controller.AddRelationShip(*did, Authentication, remainUrl, 0)
	if err == nil {
		t.Error("There should report an error when trying to update dactivated did")
		return
	}

	err = controller.AddRelationShip(*did, AssertionMethod, remainUrl, 0)
	if err == nil {
		t.Error("There should report an error when trying to update dactivated did")
		return
	}

	err = controller.AddRelationShip(*did, CapabilityDelegation, remainUrl, 0)
	if err == nil {
		t.Error("There should report an error when trying to update dactivated did")
		return
	}

	err = controller.AddRelationShip(*did, Recovery, remainUrl, 0)
	if err == nil {
		t.Error("There should report an error when trying to update dactivated did")
		return
	}
}

func TestAAA(t *testing.T) {
	sks, _, err := ToPublicKeys([]string{globalPrivateKey1, globalPrivateKey2, globalPrivateKey3, globalPrivateKey4, globalPrivateKey5})
	if err != nil {
		t.Error(err.Error())
		return
	}
	t.Log(crypto.PubkeyToAddress(sks[0].PublicKey))
	t.Log(crypto.PubkeyToAddress(sks[1].PublicKey))
	t.Log(crypto.PubkeyToAddress(sks[2].PublicKey))
	t.Log(crypto.PubkeyToAddress(sks[3].PublicKey))
	t.Log(crypto.PubkeyToAddress(sks[4].PublicKey))
}

func TestUpdateByController(t *testing.T) {
	sks, pks, err := ToPublicKeys([]string{globalPrivateKey1, globalPrivateKey2, globalPrivateKey3, globalPrivateKey4, globalPrivateKey5})
	if err != nil {
		t.Error(err.Error())
		return
	}

	//used for generate controller
	privateKey1 := sks[0]
	privateKey2 := sks[1]
	privateKey3 := sks[2]

	// used for register did
	masterKey1 := pks[0]
	masterKey2 := pks[1]
	masterKey3 := pks[2]

	// used for verification method
	pk4 := pks[3]
	pk5 := pks[4]

	d1 := &MemoDIDDocument{}
	d2 := &MemoDIDDocument{}
	d3 := &MemoDIDDocument{}

	controller1, err := NewMemoDIDController(privateKey1, "dev")
	if err != nil {
		t.Error(err.Error())
		return
	}
	controller2, err := NewMemoDIDController(privateKey2, "dev")
	if err != nil {
		t.Error(err.Error())
		return
	}
	controller3, err := NewMemoDIDController(privateKey3, "dev")
	if err != nil {
		t.Error(err.Error())
		return
	}
	resolver, err := NewMemoDIDResolver("dev")
	if err != nil {
		t.Error(err.Error())
		return
	}

	did1 := controller1.DID()
	did2 := controller2.DID()
	did3 := controller3.DID()
	//
	// register did
	err = controller1.RegisterDID()
	if err != nil {
		t.Error(err.Error())
		return
	}
	err = controller2.RegisterDID()
	if err != nil {
		t.Error(err.Error())
		return
	}
	err = controller3.RegisterDID()
	if err != nil {
		t.Error(err.Error())
		return
	}

	document1, err := resolver.Resolve(did1.String())
	if err != nil {
		t.Error(err.Error())
		return
	}
	document2, err := resolver.Resolve(did2.String())
	if err != nil {
		t.Error(err.Error())
		return
	}
	document3, err := resolver.Resolve(did3.String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	verificationMethod1, err := genVerificationMethod(did1, 0, nil, "EcdsaSecp256k1VerificationKey2019", masterKey1)
	if err != nil {
		t.Error(err.Error())
		return
	}
	verificationMethod2, err := genVerificationMethod(did2, 0, nil, "EcdsaSecp256k1VerificationKey2019", masterKey2)
	if err != nil {
		t.Error(err.Error())
		return
	}
	verificationMethod3, err := genVerificationMethod(did3, 0, nil, "EcdsaSecp256k1VerificationKey2019", masterKey3)
	if err != nil {
		t.Error(err.Error())
		return
	}

	d1.Context = DefaultContext
	d1.ID = *did1
	d1.VerificationMethod = append(d1.VerificationMethod, verificationMethod1)
	d2.Context = DefaultContext
	d2.ID = *did2
	d2.VerificationMethod = append(d2.VerificationMethod, verificationMethod2)
	d3.Context = DefaultContext
	d3.ID = *did3
	d3.VerificationMethod = append(d3.VerificationMethod, verificationMethod3)
	if !reflect.DeepEqual(document1, d1) {
		t.Error("Unexpect result")
		return
	}
	if !reflect.DeepEqual(document2, d2) {
		t.Error("Unexpect result")
		return
	}
	if !reflect.DeepEqual(document3, d3) {
		t.Error("Unexpect result")
		return
	}

	//
	// add verification method by unauthorized controller
	// calling contract will fail
	err = controller1.AddVerificationMethod(*did2, "EcdsaSecp256k1VerificationKey2019", *did1, pk4)
	if err == nil {
		t.Errorf("(%s) cannot control (%s)", did1.String(), did2.String())
		return
	}

	//
	// add verification method by authorized controller
	// calling the contract will success
	err = controller2.AddController(*did2, *did1)
	if err != nil {
		t.Error(err.Error())
		return
	}
	d2.Controller = append(d2.Controller, *did1)

	err = controller1.AddVerificationMethod(*did2, "EcdsaSecp256k1VerificationKey2019", *did1, pk5)
	if err != nil {
		t.Error(err.Error())
		return
	}
	verificationMethod, err := genVerificationMethod(did2, 1, did1, "EcdsaSecp256k1VerificationKey2019", pk5)
	if err != nil {
		t.Error(err.Error())
		return
	}
	d2.VerificationMethod = append(d2.VerificationMethod, verificationMethod)

	document2, err = resolver.Resolve(did2.String())
	if err != nil {
		t.Error(err.Error(), did2.String())
		return
	}

	if !reflect.DeepEqual(document2, d2) {
		t.Error("Unexpect result")
		return
	}

	//
	// add controller by authorized controller
	err = controller1.AddController(*did2, *did3)
	if err != nil {
		t.Error(err.Error())
		return
	}
	d2.Controller = append(d2.Controller, *did3)

	err = controller1.AddRelationShip(*did2, Authentication, document2.VerificationMethod[0].ID, 0)
	if err != nil {
		t.Error(err.Error())
		return
	}
	d2.Authentication = append(d2.Authentication, d2.VerificationMethod[0].ID)

	err = controller2.AddRelationShip(*did2, AssertionMethod, document2.VerificationMethod[1].ID, 0)
	if err != nil {
		t.Error(err.Error())
		return
	}
	d2.AssertionMethod = append(d2.AssertionMethod, d2.VerificationMethod[1].ID)

	err = controller3.AddRelationShip(*did2, CapabilityDelegation, document2.VerificationMethod[1].ID, time.Now().Add(24*time.Hour).Unix())
	if err != nil {
		t.Error(err.Error())
		return
	}
	d2.CapabilityDelegation = append(d2.CapabilityDelegation, d2.VerificationMethod[1].ID)

	err = controller1.AddRelationShip(*did2, Recovery, document2.VerificationMethod[1].ID, 0)
	if err != nil {
		t.Error(err.Error())
	}
	d2.Recovery = append(d2.Recovery, d2.VerificationMethod[1].ID)

	document2, err = resolver.Resolve(did2.String())
	if err != nil {
		t.Error(err.Error())
		return
	}

	data, _ := json.MarshalIndent(document2, " ", "\t")
	t.Log(string(data))
	data, _ = json.MarshalIndent(d2, " ", "\t")
	t.Log(string(data))

	if !reflect.DeepEqual(document2, d2) {
		t.Error("Unexpect result")
		return
	}
}

func TestGetSK(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Error(err.Error())
		return
	}

	t.Log(hex.EncodeToString(crypto.FromECDSA(privateKey)))
}

func TestResolve(t *testing.T) {
	resolver, err := NewMemoDIDResolver("dev")
	if err != nil {
		t.Error(err.Error())
		return
	}

	start := time.Now()
	document, err := resolver.Resolve("did:memo:a467507d0095681bcb0fa5301d7f4ed6212f3efeaa6160f8619c8f94206664ce")
	if err != nil {
		t.Error(err.Error())
		return
	}
	t.Log(time.Since(start).Seconds())

	documentBytes, err := json.MarshalIndent(document, "", "\t")
	if err != nil {
		t.Error(err.Error())
		return
	}

	fmt.Println(string(documentBytes))
}

func TestDerefrence(t *testing.T) {
	resolver, err := NewMemoDIDResolver("dev")
	if err != nil {
		t.Error(err.Error())
		return
	}

	_, publicKey, err := resolver.Dereference("did:memo:bbe9144474d97a23cede89c8805ba9f5710f0fcc59162eff70c5579d2505e037#masterKey")
	if err != nil {
		t.Error(err.Error())
		return
	}

	t.Log(publicKey)
}
