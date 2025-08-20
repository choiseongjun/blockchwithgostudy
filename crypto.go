package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

// PrivateKey represents an ECDSA private key
type PrivateKey struct {
	key *ecdsa.PrivateKey
}

// PublicKey represents an ECDSA public key
type PublicKey struct {
	key *ecdsa.PublicKey
}

// Address represents a blockchain address derived from public key
type Address string

// Signature represents a digital signature
type Signature struct {
	R *big.Int `json:"r"`
	S *big.Int `json:"s"`
}

// GenerateKeyPair generates a new ECDSA key pair
func GenerateKeyPair() (*PrivateKey, *PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	privKey := &PrivateKey{key: privateKey}
	pubKey := &PublicKey{key: &privateKey.PublicKey}

	return privKey, pubKey, nil
}

// ToHex converts private key to hex string
func (pk *PrivateKey) ToHex() string {
	return fmt.Sprintf("%064x", pk.key.D)
}

// FromHex creates private key from hex string
func PrivateKeyFromHex(hexStr string) (*PrivateKey, error) {
	if len(hexStr) > 2 && hexStr[:2] == "0x" {
		hexStr = hexStr[2:]
	}
	
	d, ok := new(big.Int).SetString(hexStr, 16)
	if !ok {
		return nil, fmt.Errorf("invalid hex string")
	}

	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
		},
		D: d,
	}
	
	privateKey.PublicKey.X, privateKey.PublicKey.Y = elliptic.P256().ScalarBaseMult(d.Bytes())

	return &PrivateKey{key: privateKey}, nil
}

// GetPublicKey returns the corresponding public key
func (pk *PrivateKey) GetPublicKey() *PublicKey {
	return &PublicKey{key: &pk.key.PublicKey}
}

// ToHex converts public key to hex string
func (pk *PublicKey) ToHex() string {
	return fmt.Sprintf("%064x%064x", pk.key.X, pk.key.Y)
}

// PublicKeyFromHex creates public key from hex string
func PublicKeyFromHex(hexStr string) (*PublicKey, error) {
	if len(hexStr) != 128 {
		return nil, fmt.Errorf("invalid public key hex length")
	}

	x, ok1 := new(big.Int).SetString(hexStr[:64], 16)
	y, ok2 := new(big.Int).SetString(hexStr[64:], 16)

	if !ok1 || !ok2 {
		return nil, fmt.Errorf("invalid public key hex format")
	}

	publicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	return &PublicKey{key: publicKey}, nil
}

// ToAddress converts public key to blockchain address
func (pk *PublicKey) ToAddress() Address {
	// Use Keccak256 hash of public key (similar to Ethereum)
	pubKeyBytes := append(pk.key.X.Bytes(), pk.key.Y.Bytes()...)
	hash := Keccak256(pubKeyBytes)
	
	// Take last 20 bytes and convert to hex
	address := hex.EncodeToString(hash[12:])
	return Address("0x" + address)
}

// Sign creates a digital signature for the given data
func (pk *PrivateKey) Sign(data []byte) (*Signature, error) {
	// Hash the data first
	hash := sha256.Sum256(data)
	
	r, s, err := ecdsa.Sign(rand.Reader, pk.key, hash[:])
	if err != nil {
		return nil, err
	}

	return &Signature{R: r, S: s}, nil
}

// Verify verifies a signature against data and public key
func (pk *PublicKey) Verify(data []byte, sig *Signature) bool {
	hash := sha256.Sum256(data)
	return ecdsa.Verify(pk.key, hash[:], sig.R, sig.S)
}

// ToHex converts signature to hex string
func (sig *Signature) ToHex() string {
	return fmt.Sprintf("%064x%064x", sig.R, sig.S)
}

// SignatureFromHex creates signature from hex string
func SignatureFromHex(hexStr string) (*Signature, error) {
	if len(hexStr) != 128 {
		return nil, fmt.Errorf("invalid signature hex length")
	}

	r, ok1 := new(big.Int).SetString(hexStr[:64], 16)
	s, ok2 := new(big.Int).SetString(hexStr[64:], 16)

	if !ok1 || !ok2 {
		return nil, fmt.Errorf("invalid signature hex format")
	}

	return &Signature{R: r, S: s}, nil
}

// Wallet represents a wallet with key management
type Wallet struct {
	PrivateKey *PrivateKey `json:"privateKey"`
	PublicKey  *PublicKey  `json:"publicKey"`
	Address    Address     `json:"address"`
	Name       string      `json:"name"`
}

// NewWallet creates a new wallet with generated keys
func NewWallet(name string) (*Wallet, error) {
	privKey, pubKey, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	wallet := &Wallet{
		PrivateKey: privKey,
		PublicKey:  pubKey,
		Address:    pubKey.ToAddress(),
		Name:       name,
	}

	return wallet, nil
}

// WalletFromPrivateKey creates wallet from existing private key
func WalletFromPrivateKey(name, privateKeyHex string) (*Wallet, error) {
	privKey, err := PrivateKeyFromHex(privateKeyHex)
	if err != nil {
		return nil, err
	}

	pubKey := privKey.GetPublicKey()
	
	wallet := &Wallet{
		PrivateKey: privKey,
		PublicKey:  pubKey,
		Address:    pubKey.ToAddress(),
		Name:       name,
	}

	return wallet, nil
}

// SignTransaction signs a transaction with this wallet's private key
func (w *Wallet) SignTransaction(tx *Transaction) error {
	// Create data to sign (transaction without signature)
	txData := tx.GetSigningData()
	
	signature, err := w.PrivateKey.Sign(txData)
	if err != nil {
		return err
	}

	tx.Signature = signature.ToHex()
	tx.PublicKey = w.PublicKey.ToHex()
	
	return nil
}

// String returns wallet info as string
func (w *Wallet) String() string {
	return fmt.Sprintf("Wallet{Name: %s, Address: %s}", w.Name, w.Address)
}

// KeyManager manages multiple wallets
type KeyManager struct {
	wallets map[string]*Wallet
}

// NewKeyManager creates a new key manager
func NewKeyManager() *KeyManager {
	return &KeyManager{
		wallets: make(map[string]*Wallet),
	}
}

// CreateWallet creates and stores a new wallet
func (km *KeyManager) CreateWallet(name string) (*Wallet, error) {
	if _, exists := km.wallets[name]; exists {
		return nil, fmt.Errorf("wallet with name %s already exists", name)
	}

	wallet, err := NewWallet(name)
	if err != nil {
		return nil, err
	}

	km.wallets[name] = wallet
	return wallet, nil
}

// ImportWallet imports a wallet from private key
func (km *KeyManager) ImportWallet(name, privateKeyHex string) (*Wallet, error) {
	if _, exists := km.wallets[name]; exists {
		return nil, fmt.Errorf("wallet with name %s already exists", name)
	}

	wallet, err := WalletFromPrivateKey(name, privateKeyHex)
	if err != nil {
		return nil, err
	}

	km.wallets[name] = wallet
	return wallet, nil
}

// GetWallet returns wallet by name
func (km *KeyManager) GetWallet(name string) (*Wallet, bool) {
	wallet, exists := km.wallets[name]
	return wallet, exists
}

// ListWallets returns all wallet names
func (km *KeyManager) ListWallets() []string {
	names := make([]string, 0, len(km.wallets))
	for name := range km.wallets {
		names = append(names, name)
	}
	return names
}

// GetWalletByAddress returns wallet by address
func (km *KeyManager) GetWalletByAddress(address Address) (*Wallet, bool) {
	for _, wallet := range km.wallets {
		if wallet.Address == address {
			return wallet, true
		}
	}
	return nil, false
}