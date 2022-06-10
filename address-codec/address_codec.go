package addresscodec

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/ripemd160"
)

const (
	// Lengths in bytes
	AccountAddressLength   = 20
	AccountPublicKeyLength = 33
	FamilySeedLength       = 16
	NodePublicKeyLength    = 33

	// Account/classic address prefix - value is 0
	AccountAddressPrefix = 0x00
	// Account public key prefix - value is 35
	AccountPublicKeyPrefix = 0x23
	// Family seed prefix - value is 33
	FamilySeedPrefix = 0x21
	// Node/validation public key prefix - value is 28
	NodePublicKeyPrefix = 0x1C
	// ED25519 prefix - value is 237
	ED25519Prefix = 0xED
)

type CryptoAlgorithm uint8

const (
	Undefined CryptoAlgorithm = iota
	ED25519                   = ED25519Prefix
	SECP256K1                 = FamilySeedPrefix
)

func (c CryptoAlgorithm) String() string {
	switch c {
	case ED25519:
		return "ed25519"
	case SECP256K1:
		return "secp256k1"
	}
	return "unknown"
}

type EncodeLengthError struct {
	Instance string
	Input    int
	Expected int
}

func (e *EncodeLengthError) Error() string {
	return fmt.Sprintf("`%v` length should be %v not %v", e.Instance, e.Expected, e.Input)
}

type InvalidClassicAddressError struct {
	Input string
}

func (e *InvalidClassicAddressError) Error() string {
	return fmt.Sprintf("`%v` is an invalid classic address", e.Input)
}

// Returns the base58 encoding of byte slice, with the given type prefix.
// Whilst ensuring that the byte slice is the expected length.
// Arguments:
//      b: Byte slice to be encoded.
//      typePrefix: The prefix for the type to be encoded.
//      expectedLength: The expected length of the byte slice to be encoded.
//
// Returns:
//      Base58 encoded string of b.
func Encode(b []byte, typePrefix []byte, expectedLength int) string {

	if len(b) != expectedLength {
		return ""
	}

	return Base58CheckEncode(b, typePrefix[0])
}

// Returns the byte slice decoding of the base58-encoded string and prefix.
// Arguments:
//      b58string: A base58 value.
//      typePrefix: Prefix prepended to the byte slice.
//
// Returns:
//      Decoded base58 string in a byte slice.
//      prefix.
//      Error if b58string prefix and typePrefix not equal.
func Decode(b58string string, typePrefix []byte) ([]byte, byte, error) {

	prefixLength := len(typePrefix)

	if !bytes.Equal(DecodeBase58(b58string)[:prefixLength], typePrefix) {
		return nil, 0, errors.New("b58string prefix and typeprefix not equal")
	}

	return Base58CheckDecode(b58string)
}

// Returns the classic address from public key hex string.
// Arguments:
//       pubkeyhex: public key in hex string form
//
// Returns:
//       Classic address encoding of the hex string as a base58 string.
func EncodeClassicAddressFromPublicKeyHex(pubkeyhex string, typePrefix []byte) (string, error) {

	if len(typePrefix) != 1 {
		return "", &EncodeLengthError{Instance: "TypePrefix", Expected: 1, Input: len(typePrefix)}
	}

	pubkey, err := hex.DecodeString(pubkeyhex)

	if len(pubkey) != AccountPublicKeyLength {
		pubkey = append([]byte{ED25519Prefix}, pubkey...)
	}

	if err != nil {
		return "", &EncodeLengthError{Instance: "PublicKey", Expected: AccountPublicKeyLength, Input: len(pubkey)}
	}

	accountID := sha256RipeMD160(pubkey)

	if len(accountID) != AccountAddressLength {
		return "", &EncodeLengthError{Instance: "AccountID", Expected: AccountAddressLength, Input: len(accountID)}
	}

	address := Base58CheckEncode(accountID, AccountAddressPrefix)

	if !IsValidClassicAddress(address) {
		return "", &InvalidClassicAddressError{Input: address}
	}

	return address, nil
}

// Returns the decoded byte slice of the classic address.
// Arguments:
//      cAddress: Classic address to be decoded
//
// Returns:
//      typePrefix: The type prefix byte slice of the classic address.
//      accountID: The decoded byte slice of the classic address.
func DecodeClassicAddressToAccountID(cAddress string) (typePrefix, accountID []byte, err error) {

	if len(DecodeBase58(cAddress)) != 25 {
		return nil, nil, &InvalidClassicAddressError{Input: cAddress}
	}

	return DecodeBase58(cAddress)[:1], DecodeBase58(cAddress)[1:21], nil

}

func IsValidClassicAddress(cAddress string) bool {
	_, _, c := DecodeClassicAddressToAccountID(cAddress)

	return c == nil
}

// Returns the node public key encoding of the byte slice as a base58 string.
// Arguments:
//      b: Byte slice to be encoded.
//
// Returns:
//      The node public key encoding of the byte slice as a base58 string.
func EncodeNodePublicKey(b []byte) (string, error) {

	return "", nil
}

// Returns a base58 encoding of a seed.
// Arguments:
//      entropy: Entropy bytes of FamilySeedLength.
//      encodingType: Either ED25519 or SECP256K1.
//
// Returns:
//      Encoded seed.
//      Error if entropy is not of length FamilySeedLength.
func EncodeSeed(entropy []byte, encodingType CryptoAlgorithm) (string, error) {

	if len(entropy) != FamilySeedLength {
		return "", &EncodeLengthError{Instance: "Entropy", Input: len(entropy), Expected: FamilySeedLength}
	}

	switch encodingType {
	case ED25519:
		prefix := []byte{ED25519}
		return Encode(entropy, prefix, FamilySeedLength), nil
	case SECP256K1:
		prefix := []byte{SECP256K1}
		return Encode(entropy, prefix, FamilySeedLength), nil
	default:
		return "", errors.New("encoding type must be `ed25519` or `secp256k1`")
	}

}

// Returns decoded seed and its algorithm.
// Arguments:
//      seed: base58 encoding of a seed.
//
// Returns:
//      Decoded seed and its algorithm (ED25519 or SECP256K1).
//      Error if the seed is invalid.
func DecodeSeed(seed string) ([]byte, CryptoAlgorithm, error) {

	entropy, prefix, err := Base58CheckDecode(seed)

	switch prefix {

	case ED25519:
		if err == nil {
			return entropy, ED25519, nil
		}
	case SECP256K1:
		if err == nil {
			return entropy, SECP256K1, nil
		}
	}
	return nil, 0, errors.New("invalid seed; could not determine encoding algorithm")
}

// Returns byte slice of a double hashed given byte slice.
// The given byte slice is SHA256 hashed, then the result is RIPEMD160 hashed.
func sha256RipeMD160(b []byte) []byte {
	sha256 := sha256.New()
	sha256.Write(b)

	ripemd160 := ripemd160.New()
	ripemd160.Write(sha256.Sum(nil))

	return ripemd160.Sum(nil)
}
