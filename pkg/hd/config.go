package hd

import (
	"fmt"

	"github.com/datachainlab/ibc-hd-signer/pkg/wallet"
	"github.com/hyperledger-labs/yui-relayer/signer"
)

var _ signer.SignerConfig = (*SignerConfig)(nil)

func (c *SignerConfig) Validate() error {
	if _, err := wallet.GetPrvKeyFromMnemonicAndHDWPath(c.Mnemonic, c.Path); err != nil {
		return fmt.Errorf("invalid mnemonic and/or path for HD wallet: %v", err)
	}
	return nil
}

func (c *SignerConfig) Build() (signer.Signer, error) {
	return NewSigner(c.Mnemonic, c.Path)
}
