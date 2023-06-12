package memodid

import (
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/memoio/did-solidity/go-contracts/proxy"
)

type MemoDIDDocument struct {
	Context              string               `json:"@context"`
	ID                   MemoDID              `json:"id"`
	Controller           []MemoDID            `json:"controller,omitempty"`
	VerificationMethod   []VerificationMethod `json:"verifycationMethod"`
	Authentication       []MemoDIDUrl         `json:"authentication,omitempty"`
	AssertionMethod      []MemoDIDUrl         `json:"assertionMethod,omitempty"`
	CapabilityDelegation []MemoDIDUrl         `json:"capabilityDelegation,omitempty"`
	Recovery             []MemoDIDUrl         `json:"recovery,omitempty"`
}

type VerificationMethod struct {
	ID           MemoDIDUrl `json:"id"`
	Controller   MemoDID    `json:"controller"`
	Type         string     `json:"type"`
	PublicKeyHex string     `json:"publicKeyHex"`
}

func FromSolityData(did *MemoDID, methodIndex int64, method *proxy.IAccountDidPublicKey) (*VerificationMethod, error) {
	if method.Controller == "" {
		method.Controller = "did:memo:0000000000000000000000000000000000000000000000000000000000000000"
	} else {
		method.Controller = "did:memo:" + method.Controller
	}

	controller, err := ParseMemoDID(method.Controller)
	if err != nil {
		return nil, err
	}

	didUrl, err := did.DIDUrl(methodIndex)
	if err != nil {
		return nil, err
	}

	publicKeyHex := hexutil.Encode(method.PubKeyData)
	return &VerificationMethod{
		ID:           *didUrl,
		Controller:   *controller,
		Type:         method.MethodType,
		PublicKeyHex: publicKeyHex,
	}, nil
}

func ToSolidityData(method *VerificationMethod) (*proxy.IAccountDidPublicKey, error) {
	publicKeyData, err := hexutil.Decode(method.PublicKeyHex)
	if err != nil {
		return nil, err
	}
	return &proxy.IAccountDidPublicKey{
		Controller: method.Controller.String(),
		MethodType: method.Type,
		PubKeyData: publicKeyData,
	}, nil
}

// func (v VerificationMethod) MarshalJSON() ([]byte, error) {
// 	return json.Marshal(v)
// }
