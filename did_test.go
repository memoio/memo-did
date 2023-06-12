package memodid

import (
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

// func createKeyPair() (string, string, error) {
// 	privateKey, err := crypto.GenerateKey()
// 	if err != nil {
// 		return "", "", err
// 	}

// 	publicKey := privateKey.Public()
// 	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
// 	if !ok {
// 		return "", "", xerrors.Errorf("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
// 	}

// 	return hexutil.Encode(crypto.FromECDSA(privateKey)), hexutil.Encode(crypto.CompressPubkey(publicKeyECDSA)), nil
// }

func TestParseDID(t *testing.T) {
	identify := hex.EncodeToString(crypto.Keccak256([]byte("hello")))
	didString1 := "did:memo:0x" + identify
	didString2 := "did:memo:ieuydhrndjcnfjs.sdfegreccc"
	didString3 := "dim:memo:" + identify
	didString4 := "did:example:" + identify
	didString5 := "did:memo:" + identify

	_, err := ParseMemoDID(didString1)
	if err == nil {
		t.Errorf("Parsing an unsupported did(%s) should report an error", didString1)
	}

	_, err = ParseMemoDID(didString2)
	if err == nil {
		t.Errorf("Parsing an unsupported did(%s) should report an error", didString2)
	}

	_, err = ParseMemoDID(didString3)
	if err == nil {
		t.Errorf("Parsing an unsupported did(%s) should report an error", didString3)
	}

	_, err = ParseMemoDID(didString4)
	if err == nil {
		t.Errorf("Parsing an unsupported did(%s) should report an error", didString4)
	}

	_, err = ParseMemoDID(didString5)
	if err != nil {
		t.Errorf("Parsing %s should not report an error", didString5)
	}
}

func TestMarshDID(t *testing.T) {
	identify := hex.EncodeToString(crypto.Keccak256([]byte("hello")))
	didString := "did:memo:" + identify

	did, err := ParseMemoDID(didString)
	if err != nil {
		t.Errorf("Can't parse did: %s", err.Error())
		return
	}

	data, err := json.Marshal(did)
	if err != nil {
		t.Errorf("Can't marshal did: %s", err.Error())
		return
	}
	t.Log(string(data))
}

func TestUnmarshlDID(t *testing.T) {
	identify := hex.EncodeToString(crypto.Keccak256([]byte("hello")))
	didString := "did:memo:" + identify

	did, err := ParseMemoDID(didString)
	if err != nil {
		t.Errorf("Can't parse did: %s", err.Error())
		return
	}

	data, err := json.Marshal(did)
	if err != nil {
		t.Errorf("Can't marshal did: %s", err.Error())
		return
	}

	var did1 MemoDID
	err = json.Unmarshal(data, &did1)
	if err != nil {
		t.Errorf("Can't Unmarshal did: %s", err.Error())
		return
	}

	t.Log(did)

	if did.String() != didString {
		t.Errorf("Unmarshaled did is not equal to expected")
		return
	}
}

func TestParseDIDUrl(t *testing.T) {
	identify := hex.EncodeToString(crypto.Keccak256([]byte("hello")))
	fragment1 := "#masterKey"
	fragment2 := "#key-1"
	fragment3 := "#key-256"
	fragment4 := "#ss"
	query := "?a=1"
	didUrlString1 := "did:memo:ieuydhrndjcnfjs.sdfegreccc" + fragment1
	didUrlString2 := "did:example:" + identify + fragment1
	didUrlString3 := "did:memo:" + identify + fragment1
	didUrlString4 := "did:memo:" + identify + fragment2
	didUrlString5 := "did:memo:" + identify + fragment3
	didUrlString6 := "did:memo:" + identify + fragment4
	didUrlString7 := "did:memo:" + identify + fragment3 + query

	_, err := ParseMemoDIDUrl(didUrlString1)
	if err == nil {
		t.Errorf("Parsing an unsupported did(%s) should report an error", didUrlString1)
	}

	_, err = ParseMemoDIDUrl(didUrlString2)
	if err == nil {
		t.Errorf("Parsing an unsupported did(%s) should report an error", didUrlString2)
	}

	_, err = ParseMemoDIDUrl(didUrlString3)
	if err != nil {
		t.Errorf("Parsing %s should not report an error", didUrlString3)
	}

	_, err = ParseMemoDIDUrl(didUrlString4)
	if err != nil {
		t.Errorf("Parsing %s should not report an error", didUrlString4)
	}

	_, err = ParseMemoDIDUrl(didUrlString5)
	if err != nil {
		t.Errorf("Parsing %s should not report an error", didUrlString5)
	}

	_, err = ParseMemoDIDUrl(didUrlString6)
	if err == nil {
		t.Errorf("Parsing an unsupported did(%s) should report an error", didUrlString6)
	}

	_, err = ParseMemoDIDUrl(didUrlString7)
	if err == nil {
		t.Errorf("Parsing an unsupported did(%s) should report an error", didUrlString7)
	}
}

func TestHex(t *testing.T) {
	num, _ := hexutil.DecodeBig("0x59d8")

	t.Log(num)
}

func TestUnix(t *testing.T) {
	t.Log(time.Now().Unix())
}
