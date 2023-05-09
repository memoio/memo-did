package memodid

type DIDController interface {
	// Create
	RegisterDID(publicKeyHex string) error

	// Update
	AddController(did MemoDID, controller MemoDID) error
	DeactivateController(did MemoDID, controller MemoDID) error
	AddVerificationMethod(did MemoDID, vtype string, controller MemoDID, publicKeyHex string) error
	UpdateVerificationMethod(didUrl MemoDIDUrl, vtype string, publicKeyHex string) error
	DeactivateVerificationMethod(didUrl MemoDIDUrl) error
	// Relation ship include: authentication; assertionMethod; capabilityDelegation; recovery
	AddRelationShip(did MemoDID, relationType int, didUrl MemoDIDUrl, expireTime int64) error
	DeactivateRelationShip(did MemoDID, relationType int, didUrl MemoDIDUrl) error

	// Delete
	DeactivateDID(did MemoDID) error
}

type DIDResolver interface {
	// Read
	Resolve(didString string) (*MemoDIDDocument, error)
	Derefrence(didUrlString string) (string, string, error)
}
