package hd

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	"github.com/datachainlab/ibc-hd-signer/pkg/wallet"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/hyperledger-labs/yui-relayer/signer"
)

var _ signer.Signer = (*Signer)(nil)

type Signer struct {
	key *ecdsa.PrivateKey
}

func NewSigner(mnemonic, path string) (*Signer, error) {
	key, err := wallet.GetPrvKeyFromMnemonicAndHDWPath(mnemonic, path)
	if err != nil {
		return nil, fmt.Errorf("failed to extract a private key from the HD wallet")
	}
	return &Signer{key}, nil
}

func (s *Signer) GetPublicKey(_ context.Context) ([]byte, error) {
	return gethcrypto.CompressPubkey(&s.key.PublicKey), nil
}

func (s *Signer) Sign(_ context.Context, digest []byte) ([]byte, error) {
	sig, err := gethcrypto.Sign(digest, s.key)
	if err != nil {
		return nil, fmt.Errorf("failed to sign tx: %v", err)
	}

	return sig, nil
}
