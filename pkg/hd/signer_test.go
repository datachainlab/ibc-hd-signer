package hd

import (
	"context"
	"encoding/hex"
	"slices"
	"testing"
)

func TestGetPublicKey(t *testing.T) {
	cases := []struct {
		mnemonic string
		path     string
		expected string
		isErr    bool
	}{
		{
			isErr:    false,
			mnemonic: "math razor capable expose worth grape metal sunset metal sudden usage scheme",
			path:     "m/44'/60'/0'/0/0",
			expected: "039091a0bc2537530b4eb35672624c147db7c70c986929ede18c8efc2299153399",
		},
	}

	for _, c := range cases {
		signer, err := NewSigner(c.mnemonic, c.path)
		if err != nil {
			t.Errorf("fail to NewSigner(%s, %s): %v", c.mnemonic, c.path, err)
			continue
		}

		pkBytes, err := signer.GetPublicKey(context.Background())
		if c.isErr {
			if err == nil {
				t.Errorf("GetPublicKey(%s, %s) unexpectedly returned %v", c.mnemonic, c.path, pkBytes)
			}
		} else if err != nil {
			t.Errorf("GetPublicKey(%s, %s) unexpectedly failed: %v", c.mnemonic, c.path, err)
		} else {
			expectBytes, err := hex.DecodeString(c.expected)
			if err != nil {
				t.Errorf("fail to hex.DecodeString(%s): %v", c.expected, err)
			} else if !slices.Equal(expectBytes, pkBytes) {
				t.Errorf("GetPublicKey(%s, %s) results %v but expect %s", c.mnemonic, c.path, pkBytes, expectBytes)
			}
		}
	}
}

func TestSign(t *testing.T) {
	cases := []struct {
		mnemonic string
		path     string
		expected string
		isErr    bool
	}{
		{
			isErr:    false,
			mnemonic: "math razor capable expose worth grape metal sunset metal sudden usage scheme",
			path:     "m/44'/60'/0'/0/0",
			expected: "26ea079b2a54dcec61c9988d4d92eb7ec8922114304d63a3ea2181e39d463484079db88a00f56630fda76a2fd5d83d57dc551784521d8160e6695483f099739700",
		},
	}

	digest := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	for _, c := range cases {
		signer, err := NewSigner(c.mnemonic, c.path)
		if err != nil {
			t.Errorf("fail to NewSigner(%s, %s): %v", c.mnemonic, c.path, err)
			continue
		}

		sign, err := signer.Sign(context.Background(), digest)
		if c.isErr {
			if err == nil {
				t.Errorf("Sign(%s, %s) unexpectedly returned %v", c.mnemonic, c.path, sign)
			}
		} else if err != nil {
			t.Errorf("Sign(%s, %s) unexpectedly failed: %v", c.mnemonic, c.path, err)
		} else {
			expectBytes, err := hex.DecodeString(c.expected)
			if err != nil {
				t.Errorf("fail to hex.DecodeString(%s): %v", c.expected, err)
			} else if !slices.Equal(expectBytes, sign) {
				t.Errorf("Sign(%s, %s) results %v but expect %s", c.mnemonic, c.path, sign, expectBytes)
			}
		}
	}
}
