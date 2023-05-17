package memodid

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"time"

	// "memo"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/xerrors"

	com "github.com/memoio/contractsv2/common"
	inst "github.com/memoio/contractsv2/go_contracts/instance"
	"github.com/memoio/did-solidity/go-contracts/proxy"
)

var (
	checkTxSleepTime = 6 // 先等待6s（出块时间加1）
	nextBlockTime    = 5 // 出块时间5s
)

type MemoDIDController struct {
	did           *MemoDID
	endpoint      string
	privateKey    *ecdsa.PrivateKey
	didTransactor *bind.TransactOpts
	proxyAddr     common.Address
}

var _ DIDController = &MemoDIDController{}

func NewMemoDIDController(privateKey *ecdsa.PrivateKey, chain string) (*MemoDIDController, error) {
	did, err := CreatMemoDID(privateKey, chain)
	if err != nil {
		return nil, err
	}
	controller, err := NewMemoDIDControllerWithDID(privateKey, chain, did.String())
	return controller, err
}

func NewMemoDIDControllerWithDID(privateKey *ecdsa.PrivateKey, chain, didString string) (*MemoDIDController, error) {
	instanceAddr, endpoint := com.GetInsEndPointByChain(chain)

	client, err := ethclient.DialContext(context.TODO(), endpoint)
	if err != nil {
		return nil, err
	}

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		chainID = big.NewInt(666)
	}

	// new instanceIns
	instanceIns, err := inst.NewInstance(instanceAddr, client)
	if err != nil {
		return nil, err
	}

	// get proxyAddr
	proxyAddr, err := instanceIns.Instances(&bind.CallOpts{}, com.TypeDidProxy)
	if err != nil {
		return nil, err
	}

	// new auth
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
	if err != nil {
		return nil, err
	}
	auth.Value = big.NewInt(0)     // in wei
	auth.GasLimit = uint64(300000) // in units
	auth.GasPrice = big.NewInt(1000)

	did, err := ParseMemoDID(didString)
	return &MemoDIDController{
		did:           did,
		endpoint:      endpoint,
		privateKey:    privateKey,
		didTransactor: auth,
		proxyAddr:     proxyAddr,
	}, err
}

// Create unregistered DID
func CreatMemoDID(privateKey *ecdsa.PrivateKey, chain string) (*MemoDID, error) {
	_, endpoint := com.GetInsEndPointByChain(chain)
	client, err := ethclient.DialContext(context.TODO(), endpoint)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, xerrors.Errorf("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}
	address := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := client.PendingNonceAt(context.TODO(), address)
	if err != nil {
		return nil, err
	}

	identifier := hex.EncodeToString(crypto.Keccak256(binary.AppendUvarint(address.Bytes(), nonce)))

	return &MemoDID{
		Method:      "memo",
		Identifier:  identifier,
		Identifiers: []string{identifier},
	}, nil
}

func (c *MemoDIDController) DID() *MemoDID {
	return c.did
}

func (c *MemoDIDController) RegisterDID() error {
	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proxyIns, err := proxy.NewProxy(c.proxyAddr, client)
	if err != nil {
		return err
	}

	// Get public key from private key
	publicKey := c.privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return xerrors.Errorf("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}
	publicKeyBytes := crypto.CompressPubkey(publicKeyECDSA)

	tx, err := proxyIns.CreateDID(c.didTransactor, c.did.Identifier, "EcdsaSecp256k1VerificationKey2019", publicKeyBytes)
	if err != nil {
		return err
	}

	return CheckTx(c.endpoint, tx.Hash(), "RegisterDID")
}

// AddController will authorize the 'controller' to fully control of 'did'
// AddController will add a controller in did's document
func (c *MemoDIDController) AddController(did MemoDID, controller MemoDID) error {
	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proxyIns, err := proxy.NewProxy(c.proxyAddr, client)
	if err != nil {
		return err
	}

	tx, err := proxyIns.AddController(c.didTransactor, did.Identifier, c.did.Identifier, controller.Identifier)
	if err != nil {
		return err
	}

	return CheckTx(c.endpoint, tx.Hash(), "AddController")
}

func (c *MemoDIDController) DeactivateController(did MemoDID, controller MemoDID) error {
	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proxyIns, err := proxy.NewProxy(c.proxyAddr, client)
	if err != nil {
		return err
	}

	tx, err := proxyIns.RemoveController(c.didTransactor, did.Identifier, c.did.Identifier, controller.Identifier)
	if err != nil {
		return err
	}

	return CheckTx(c.endpoint, tx.Hash(), "RemoveController")
}

func (c *MemoDIDController) AddVerificationMethod(did MemoDID, vtype string, controller MemoDID, publicKeyHex string) error {
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return err
	}

	publicKey := proxy.IAccountDidPublicKey{
		MethodType:  vtype,
		Controller:  controller.String(),
		PubKeyData:  publicKeyBytes,
		Deactivated: false,
	}

	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proxyIns, err := proxy.NewProxy(c.proxyAddr, client)
	if err != nil {
		return err
	}

	tx, err := proxyIns.AddVeri(c.didTransactor, did.Identifier, c.did.Identifier, publicKey)
	if err != nil {
		return err
	}

	return CheckTx(c.endpoint, tx.Hash(), "AddVerificationMethod")
}

func (c *MemoDIDController) UpdateVerificationMethod(didUrl MemoDIDUrl, vtype string, publicKeyHex string) error {
	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proxyIns, err := proxy.NewProxy(c.proxyAddr, client)
	if err != nil {
		return err
	}

	tx, err := proxyIns.UpdateVeri(c.didTransactor, didUrl.Identifier, big.NewInt(int64(didUrl.GetMethodIndex())), vtype, []byte(publicKeyHex))
	if err != nil {
		return err
	}
	return CheckTx(c.endpoint, tx.Hash(), "UpdateVerificationMethod")
}

func (c *MemoDIDController) DeactivateVerificationMethod(didUrl MemoDIDUrl) error {
	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proxyIns, err := proxy.NewProxy(c.proxyAddr, client)
	if err != nil {
		return err
	}

	tx, err := proxyIns.DeactivateVeri(c.didTransactor, didUrl.Identifier, c.did.Identifier, big.NewInt(int64(didUrl.GetMethodIndex())), true)
	if err != nil {
		return err
	}

	return CheckTx(c.endpoint, tx.Hash(), "DeactivateVerificationMethod")
}

func (c *MemoDIDController) AddRelationShip(did MemoDID, relationType int, didUrl MemoDIDUrl, expireTime int64) error {
	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proxyIns, err := proxy.NewProxy(c.proxyAddr, client)
	if err != nil {
		return err
	}

	var tx *types.Transaction
	switch relationType {
	case Authentication:
		tx, err = proxyIns.AddAuth(c.didTransactor, did.Identifier, c.did.Identifier, didUrl.String())
	case AssertionMethod:
		tx, err = proxyIns.AddAssertion(c.didTransactor, did.Identifier, c.did.Identifier, didUrl.String())
	case CapabilityDelegation:
		tx, err = proxyIns.AddDelegation(c.didTransactor, did.Identifier, c.did.Identifier, didUrl.String(), big.NewInt(expireTime))
	case Recovery:
		tx, err = proxyIns.AddRecovery(c.didTransactor, did.Identifier, c.did.Identifier, didUrl.String())
	default:
		return xerrors.Errorf("unsupported relation ships")
	}
	if err != nil {
		return err
	}

	return CheckTx(c.endpoint, tx.Hash(), "AddRelationShip")
}

func (c *MemoDIDController) DeactivateRelationShip(did MemoDID, relationType int, didUrl MemoDIDUrl) error {
	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proxyIns, err := proxy.NewProxy(c.proxyAddr, client)
	if err != nil {
		return err
	}

	var tx *types.Transaction
	switch relationType {
	case Authentication:
		tx, err = proxyIns.RemoveAuth(c.didTransactor, did.Identifier, c.did.Identifier, didUrl.String())
	case AssertionMethod:
		tx, err = proxyIns.RemoveAssertion(c.didTransactor, did.Identifier, c.did.Identifier, didUrl.String())
	case CapabilityDelegation:
		tx, err = proxyIns.RemoveDelegation(c.didTransactor, did.Identifier, c.did.Identifier, didUrl.String())
	case Recovery:
		tx, err = proxyIns.RemoveRecovery(c.didTransactor, did.Identifier, c.did.Identifier, didUrl.String())
	default:
		return xerrors.Errorf("unsupported relation ships")
	}
	if err != nil {
		return err
	}

	return CheckTx(c.endpoint, tx.Hash(), "DeactivateRelationShip")
}

func (c *MemoDIDController) DeactivateDID(did MemoDID) error {
	client, err := ethclient.DialContext(context.TODO(), c.endpoint)
	if err != nil {
		return err
	}
	defer client.Close()

	proxyIns, err := proxy.NewProxy(c.proxyAddr, client)
	if err != nil {
		return err
	}

	tx, err := proxyIns.DeactivateDID(c.didTransactor, did.Identifier, c.did.Identifier, true)
	if err != nil {
		return err
	}

	return CheckTx(c.endpoint, tx.Hash(), "DeactivateDID")
}

// CheckTx check whether transaction is successful through receipt
func CheckTx(endPoint string, txHash common.Hash, name string) error {
	var receipt *types.Receipt

	t := checkTxSleepTime
	for i := 0; i < 10; i++ {
		time.Sleep(time.Duration(t) * time.Second)
		receipt = com.GetTransactionReceipt(endPoint, txHash)
		if receipt != nil {
			break
		}
		t = nextBlockTime
	}

	if receipt == nil {
		return xerrors.Errorf("%s: cann't get transaction(%s) receipt, not packaged", name, txHash)
	}

	// 0 means fail
	if receipt.Status == 0 {
		if receipt.GasUsed != receipt.CumulativeGasUsed {
			return xerrors.Errorf("%s: transaction(%s) exceed gas limit", name, txHash)
		}
		return xerrors.Errorf("%s: transaction(%s) mined but execution failed, please check your tx input", name, txHash)
	}
	return nil
}
