package wallet

import (
	"testing"
	"math/big"
	"encoding/hex"
)

func TestParseHDPathLevel(t *testing.T) {
	cases := []struct {
		data     string
		expected HDPathLevel
		isErr    bool
	}{
		{
			isErr:    false,
			data:     "m/44'/60'/0'/0/0",
			expected: HDPathLevel { 44, 60, 0, 0, 0 },
		},
		{
			isErr:    true, // invalid path level
			data:     "m/44'/60'/0'/0/0/7parts",
			expected: HDPathLevel { 44, 60, 0, 0, 0 },
		},
		{
			isErr:    true, // prefix should be 'm'
			data:     "M/44'/60'/0'/0/0",
			expected: HDPathLevel { 44, 60, 0, 0, 0 },
		},
		{
			isErr:    true, // missing apostrophe: 44
			data:     "m/44/60/0/0/0",
			expected: HDPathLevel { 44, 60, 0, 0, 0 },
		},
		{
			isErr:    true, // strconv.Atoi: parsing "str": invalid syntax
			data:     "m/str'/60'/0'/0/0",
			expected: HDPathLevel { 44, 60, 0, 0, 0 },
		},
	}

	for _, c := range cases {
		a, err := ParseHDPathLevel(c.data)
		if c.isErr {
			if err == nil {
				t.Errorf("ParseHDPathLevel(%s) unexpectedly returned %v", c.data, a)
			}
		} else if err != nil {
			t.Errorf("ParseHDPathLevel(%s) unexpectedly failed: %v", c.data, err)
		} else if *a != c.expected {
			t.Errorf("%s has been mistakenly parsed to %v, expected=%v", c.data, *a, c.expected)
		}
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		data     HDPathLevel
		isErr    bool
	}{
		{
			isErr:    false,
			data:     HDPathLevel{44, 60, 0, 0, 0},
		},
		{
			isErr:    true, // purpose should be 44
			data:     HDPathLevel{41, 60, 0, 0, 0},
		},
		{
			isErr:    true, // change should be 0 or 1
			data:     HDPathLevel{44, 60, 0, 99, 0},
		},
	}

	for _, c := range cases {
		err := c.data.Validate()
		if c.isErr {
			if err == nil {
				t.Errorf("Validate(%v) unexpectedly succeeded", c.data)
			}
		} else if err != nil {
			t.Errorf("Validate(%v) unexpectedly failed: %v", c.data, err)
		}
	}
}

func TestGetPrvKeyFromHDWallet(t *testing.T) {
	cases := []struct {
		seed   string
		path   HDPathLevel
		expect string
		isErr  bool
	}{
		{
			isErr:    false,
			seed: "5d192f43318024f6919e92a6bdf9474b34b704295abb3e21599290d7a3262b567e6c6de54545e946d54b559f06ae475e57d3964875e889a724bbe7108374965c",
			path: HDPathLevel{44, 60, 0, 0, 0},
			expect: "103621489529634167205139750085116413410837146389409995551260132005794187042961",
		},
	}

	for _, c := range cases {
		seedBytes, err := hex.DecodeString(c.seed)
		if err != nil {
			t.Errorf("invalid test case: seed=%s: %v", c.seed, err)
			continue
		}
		expect, succeed := (&big.Int{}).SetString(c.expect, 10)
		if !succeed {
			t.Errorf("invalid test case: expect=%s", c.expect)
			continue
		}

		pk, err := GetPrvKeyFromHDWallet(seedBytes, &c.path)
		if c.isErr {
			if err == nil {
				t.Errorf("GetPrvKeyFromHDWallet(%s, %v) unexpectedly succeeded", c.seed, c.path)
			}
		} else if err != nil {
			t.Errorf("GetPrvKeyFromHDWallet(%s, %v) unexpectedly failed: %v", c.seed, c.path, err)
		} else if expect.Cmp(pk.D) != 0 {
			t.Errorf("GetPrvKeyFromHDWallet(%s, %v) results %v but expect %v", c.seed, c.path, pk.D, expect)
		}
	}
}

func TestGetPrvKeyFromMnemonicAndHDPath(t *testing.T) {
	cases := []struct {
		mnemonic string
		path     string
		expect   string
		isErr    bool
	}{
		{
			isErr:    false,
			mnemonic: "math razor capable expose worth grape metal sunset metal sudden usage scheme",
			path: "m/44'/60'/0'/0/0",
			expect: "103621489529634167205139750085116413410837146389409995551260132005794187042961",
		},
	}

	for _, c := range cases {
		expect, succeed := (&big.Int{}).SetString(c.expect, 10)
		if !succeed {
			t.Errorf("invalid test case: expect=%s", c.expect)
			continue
		}

		pk, err := GetPrvKeyFromMnemonicAndHDWPath(c.mnemonic, c.path)
		if c.isErr {
			if err == nil {
				t.Errorf("GetPrvKeyFromMnemonicAndHDPath(%s, %s) unexpectedly succeeded", c.mnemonic, c.path)
			}
		} else if err != nil {
			t.Errorf("GetPrvKeyFromMnemonicAndHDPath(%s, %s) unexpectedly failed: %v", c.mnemonic, c.path, err)
		} else if expect.Cmp(pk.D) != 0 {
			t.Errorf("GetPrvKeyFromMnemonicAndHDPath(%s, %s) results %v but expect %v", c.mnemonic, c.path, pk.D, expect)
		}
	}
}
