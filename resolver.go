package memodid

import (
	"context"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/ethclient"
	com "github.com/memoio/contractsv2/common"
	inst "github.com/memoio/contractsv2/go_contracts/instance"
	"github.com/memoio/did-solidity/go-contracts/proxy"
	"golang.org/x/xerrors"
)

var DefaultContext = "https://www.w3.org/ns/did/v1"

type MemoDIDResolver struct {
	endpoint    string
	accountAddr common.Address
}

var _ DIDResolver = &MemoDIDResolver{}

func NewMemoDIDResolver(chain string) (*MemoDIDResolver, error) {
	if chain == "" {
		chain = com.DevChain
	}

	instanceAddr, endpoint := com.GetInsEndPointByChain(chain)

	client, err := ethclient.DialContext(context.TODO(), endpoint)
	if err != nil {
		return nil, err
	}

	// new instanceIns
	instanceIns, err := inst.NewInstance(instanceAddr, client)
	if err != nil {
		return nil, err
	}

	accountAddr, err := instanceIns.Instances(&bind.CallOpts{}, com.TypeAccountDid)
	if err != nil {
		return nil, err
	}

	return &MemoDIDResolver{
		endpoint:    endpoint,
		accountAddr: accountAddr,
	}, nil
}

func (r *MemoDIDResolver) Resolve(didString string) (*MemoDIDDocument, error) {
	did, err := ParseMemoDID(didString)
	if err != nil {
		return nil, err
	}

	client, err := ethclient.DialContext(context.TODO(), r.endpoint)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	accountIns, err := proxy.NewIAccountDid(r.accountAddr, client)
	if err != nil {
		return nil, err
	}

	dactivated, err := accountIns.IsDeactivated(&bind.CallOpts{}, did.Identifier)
	if err != nil {
		return nil, err
	}
	if dactivated {
		return &MemoDIDDocument{}, nil
	}

	controllers, err := queryAllController(accountIns, did)
	if err != nil {
		return nil, err
	}
	verificationMethods, err := queryAllVerificationMethod(accountIns, did)
	if err != nil {
		return nil, err
	}
	authentications, err := queryAllAuthtication(accountIns, did)
	if err != nil {
		return nil, err
	}
	assertions, err := queryAllAssertion(accountIns, did)
	if err != nil {
		return nil, err
	}
	delegation, err := queryAllDelagation(accountIns, did)
	if err != nil {
		return nil, err
	}
	recovery, err := queryAllRecovery(accountIns, did)
	if err != nil {
		return nil, err
	}

	return &MemoDIDDocument{
		Context:              DefaultContext,
		ID:                   *did,
		Controller:           controllers,
		VerificationMethod:   verificationMethods,
		Authentication:       authentications,
		AssertionMethod:      assertions,
		CapabilityDelegation: delegation,
		Recovery:             recovery,
	}, nil
}

func (r *MemoDIDResolver) Dereference(didUrlString string) (string, string, error) {
	didUrl, err := ParseMemoDIDUrl(didUrlString)
	if err != nil {
		return "", "", err
	}

	client, err := ethclient.DialContext(context.TODO(), r.endpoint)
	if err != nil {
		return "", "", err
	}
	defer client.Close()

	accountIns, err := proxy.NewIAccountDid(r.accountAddr, client)
	if err != nil {
		return "", "", err
	}

	verifyMethod, err := accountIns.GetVeri(&bind.CallOpts{}, didUrl.Identifier, big.NewInt(int64(didUrl.GetMethodIndex())))
	if err != nil {
		return "", "", err
	}
	if verifyMethod.Deactivated {
		return "", "", xerrors.Errorf("The Verify Method(%s) is Deactivated", didUrl.String())
	}

	return verifyMethod.MethodType, hexutil.Encode(verifyMethod.PubKeyData), nil
}

func queryAllController(accountIns *proxy.IAccountDid, did *MemoDID) ([]MemoDID, error) {
	controllerIter, err := accountIns.FilterAddController(&bind.FilterOpts{}, []string{did.Identifier})
	if err != nil {
		return nil, err
	}

	var controllers []MemoDID
	for controllerIter.Next() {
		// if hex.EncodeToString(controllerIter.Event.Did[:]) != did.Identifier {
		// 	return nil, xerrors.Errorf("Got wrong did when query controller")
		// }

		// controller only supports did:memo currently, so no need to save prefix
		controller, err := ParseMemoDID("did:memo:" + controllerIter.Event.Controller)
		if err != nil {
			return nil, err
		}

		// check controller is activated or not
		activated, err := accountIns.IsController(&bind.CallOpts{}, did.Identifier, controller.Identifier)
		if err != nil {
			return nil, err
		}
		if activated {
			controllers = append(controllers, *controller)
		}
	}

	return controllers, nil
}

func queryAllVerificationMethod(accountIns *proxy.IAccountDid, did *MemoDID) ([]VerificationMethod, error) {
	size, err := accountIns.GetVeriLen(&bind.CallOpts{}, did.Identifier)
	if err != nil {
		return nil, err
	}

	var verificationMethods []VerificationMethod
	for i := int64(0); i < size.Int64(); i++ {
		verificationMethodSol, err := accountIns.GetVeri(&bind.CallOpts{}, did.Identifier, big.NewInt(i))
		if err != nil {
			return nil, err
		}
		if !verificationMethodSol.Deactivated {
			verificationMethod, err := FromSolityData(did, i, &verificationMethodSol)
			if err != nil {
				return nil, err
			}
			verificationMethods = append(verificationMethods, *verificationMethod)
		}
	}

	return verificationMethods, nil
}

func queryAllAuthtication(accountIns *proxy.IAccountDid, did *MemoDID) ([]MemoDIDUrl, error) {
	authIter, err := accountIns.FilterAddAuth(&bind.FilterOpts{}, []string{did.Identifier})
	if err != nil {
		return nil, err
	}
	defer authIter.Close()

	var authentications []MemoDIDUrl
	for authIter.Next() {
		// if hex.EncodeToString(authIter.Event.Did[:]) != did.Identifier {
		// 	return nil, xerrors.Errorf("Got wrong did when query authentication")
		// }

		// parse method id
		didUrl, err := ParseMemoDIDUrl(authIter.Event.Id)
		if err != nil {
			return nil, err
		}

		// check method id is activated or not
		activated, err := accountIns.InAuth(&bind.CallOpts{}, did.Identifier, didUrl.String())
		if err != nil {
			return nil, err
		}
		verificationMethod, err := accountIns.GetVeri(&bind.CallOpts{}, didUrl.DID().Identifier, big.NewInt(int64(didUrl.GetMethodIndex())))
		if err != nil {
			return nil, err
		}
		if activated && !verificationMethod.Deactivated {
			authentications = append(authentications, *didUrl)
		}
	}

	return authentications, nil
}

func queryAllAssertion(accountIns *proxy.IAccountDid, did *MemoDID) ([]MemoDIDUrl, error) {
	assertionIter, err := accountIns.FilterAddAssertion(&bind.FilterOpts{}, []string{did.Identifier})
	if err != nil {
		return nil, err
	}
	defer assertionIter.Close()

	var assertions []MemoDIDUrl
	for assertionIter.Next() {
		// if hex.EncodeToString(assertionIter.Event.Did[:]) != did.Identifier {
		// 	return nil, xerrors.Errorf("Got wrong did when query assertion")
		// }

		// parse method id
		didUrl, err := ParseMemoDIDUrl(assertionIter.Event.Id)
		if err != nil {
			return nil, err
		}

		// check method id is activated or not
		activated, err := accountIns.InAssertion(&bind.CallOpts{}, did.Identifier, didUrl.String())
		if err != nil {
			return nil, err
		}
		verificationMethod, err := accountIns.GetVeri(&bind.CallOpts{}, didUrl.DID().Identifier, big.NewInt(int64(didUrl.GetMethodIndex())))
		if err != nil {
			return nil, err
		}
		if activated && !verificationMethod.Deactivated {
			assertions = append(assertions, *didUrl)
		}
	}

	return assertions, nil
}

func queryAllDelagation(accountIns *proxy.IAccountDid, did *MemoDID) ([]MemoDIDUrl, error) {
	delegationIter, err := accountIns.FilterAddDelegation(&bind.FilterOpts{}, []string{did.Identifier})
	if err != nil {
		return nil, err
	}
	defer delegationIter.Close()

	var delegations []MemoDIDUrl
	for delegationIter.Next() {
		// if hex.EncodeToString(delegationIter.Event.Did[:]) != did.Identifier {
		// 	return nil, xerrors.Errorf("Got wrong did when query delegation")
		// }

		// parse method id
		didUrl, err := ParseMemoDIDUrl(delegationIter.Event.Id)
		if err != nil {
			return nil, err
		}

		// check delegation id is expired or not
		expiration, err := accountIns.InDelegation(&bind.CallOpts{}, did.Identifier, didUrl.String())
		if err != nil {
			return nil, err
		}
		verificationMethod, err := accountIns.GetVeri(&bind.CallOpts{}, didUrl.DID().Identifier, big.NewInt(int64(didUrl.GetMethodIndex())))
		if err != nil {
			return nil, err
		}
		if expiration.Int64() >= time.Now().Unix() && !verificationMethod.Deactivated {
			delegations = append(delegations, *didUrl)
		}
	}

	return delegations, nil
}

func queryAllRecovery(accountIns *proxy.IAccountDid, did *MemoDID) ([]MemoDIDUrl, error) {
	recoveryIter, err := accountIns.FilterAddRecovery(&bind.FilterOpts{}, []string{did.Identifier})
	if err != nil {
		return nil, err
	}
	defer recoveryIter.Close()

	var recovery []MemoDIDUrl
	for recoveryIter.Next() {
		// if hex.EncodeToString(recoveryIter.Event.Did[:]) != did.Identifier {
		// 	return nil, xerrors.Errorf("Got wrong did when query recovery")
		// }

		// parse method id
		didUrl, err := ParseMemoDIDUrl(recoveryIter.Event.Recovery)
		if err != nil {
			return nil, err
		}

		// check method id is activated or not
		activated, err := accountIns.InRecovery(&bind.CallOpts{}, did.Identifier, didUrl.String())
		if err != nil {
			return nil, err
		}
		verificationMethod, err := accountIns.GetVeri(&bind.CallOpts{}, didUrl.DID().Identifier, big.NewInt(int64(didUrl.GetMethodIndex())))
		if err != nil {
			return nil, err
		}
		if activated && !verificationMethod.Deactivated {
			recovery = append(recovery, *didUrl)
		}
	}

	return recovery, nil
}
