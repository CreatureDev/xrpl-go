package binarycodec

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/CreatureDev/xrpl-go/model/transactions"

	"github.com/CreatureDev/xrpl-go/binary-codec/serdes"
	"github.com/CreatureDev/xrpl-go/binary-codec/types"
)

var ErrSigningClaimFieldNotFound = errors.New("'Channel' & 'Amount' fields are both required, but were not found")

const (
	txMultiSigPrefix          = "534D5400"
	paymentChannelClaimPrefix = "434C4D00"
	txSigPrefix               = "53545800"
)

func encode(tx transactions.Tx, onlySigning bool, mutations map[string]types.FieldMutation) (string, error) {
	b, err := encodeBinary(tx, onlySigning, mutations)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(b)), nil
}

func encodeBinary(tx transactions.Tx, onlySigning bool, mutations map[string]types.FieldMutation) ([]byte, error) {
	st := &types.STObject{
		OnlySigning: onlySigning,
		Mutations:   mutations,
	}
	b, err := st.FromJson(tx)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// Encode converts a JSON transaction object to a hex string in the canonical binary format.
// The binary format is defined in XRPL's core codebase.
func Encode(tx transactions.Tx) (string, error) {
	return encode(tx, false, nil)
}

// EncodeForMultiSign: encodes a transaction into binary format in preparation for providing one
// signature towards a multi-signed transaction.
// (Only encodes fields that are intended to be signed.)
func EncodeForMultisigning(tx transactions.Tx, xrpAccountID string) ([]byte, error) {
	st := &types.AccountID{}

	suffix, err := st.FromJson(xrpAccountID)
	if err != nil {
		return nil, err
	}

	// SigningPubKey is required for multi-signing but should be set to empty string.
	err = setFieldFromTx(tx, "SigningPubKey", "placeholder", func(v any) bool {
		return v.(string) == ""
	})
	if err != nil {
		return nil, err
	}
	encoded, err := encodeBinary(tx, true, map[string]types.FieldMutation{
		"SigningPubKey": types.Zero(),
	})

	if err != nil {
		return nil, err
	}
	ret, err := hex.DecodeString(txMultiSigPrefix)
	if err != nil {
		return nil, err
	}
	ret = append(ret, encoded...)
	ret = append(ret, suffix...)

	return ret, nil
}

// Encodes a transaction into binary format in preparation for signing.
func EncodeForSigning(tx transactions.Tx) ([]byte, error) {
	encoded, err := encodeBinary(tx, true, nil)
	if err != nil {
		return nil, err
	}
	tEnc, err := encode(tx, true, nil)
	b, _ := hex.DecodeString(tEnc)
	if !reflect.DeepEqual(b, encoded) {
		return nil, fmt.Errorf("encoding mismatch\n%s\n%s\nend", hex.EncodeToString(b), hex.EncodeToString(encoded))
	}

	ret, err := hex.DecodeString(txSigPrefix)
	if err != nil {
		return nil, err
	}
	ret = append(ret, encoded...)
	return ret, nil
}

// EncodeForPaymentChannelClaim: encodes a payment channel claim into binary format in preparation for signing.
func EncodeForSigningClaim(tx transactions.PaymentChannelClaim) ([]byte, error) {

	if tx.Channel == "" || tx.Amount == 0 {
		return nil, ErrSigningClaimFieldNotFound
	}

	channel, err := types.NewHash256().FromJson(tx.Channel)

	if err != nil {
		return nil, err
	}

	t := &types.Amount{}
	amount, err := t.FromJson(tx.Amount)

	if err != nil {
		return nil, err

	}

	if bytes.HasPrefix(amount, []byte{0x40}) {
		amount = bytes.Replace(amount, []byte{0x40}, []byte{0x00}, 1)
	}
	ret, err := hex.DecodeString(paymentChannelClaimPrefix)
	if err != nil {
		return nil, err
	}
	ret = append(ret, channel...)
	ret = append(ret, amount...)

	return ret, nil
}

// Decode decodes a hex string in the canonical binary format into a JSON transaction object.
func Decode(hexEncoded string) (map[string]any, error) {
	b, err := hex.DecodeString(hexEncoded)
	if err != nil {
		return nil, err
	}
	return DecodeBinary(b)
}

// DeocdeBinary decodes canonical binary format into JSON transition object
func DecodeBinary(b []byte) (map[string]any, error) {
	p := serdes.NewBinaryParser(b)
	st := &types.STObject{}
	m, err := st.ToJson(p)
	if err != nil {
		return nil, err
	}

	return m.(map[string]any), nil

}

// Overwrites a field in a transaction with a new value if condition is met.
func setFieldFromTx(tx transactions.Tx, fieldName string, value any, condition func(any) bool) error {
	rv := reflect.ValueOf(tx)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	} else {
		return errors.New("invalid transaction")
	}
	if !rv.FieldByName(fieldName).IsValid() {
		return errors.New("invalid field name")
	}
	if condition != nil && condition(rv.FieldByName(fieldName).Interface()) {
		rv.FieldByName(fieldName).Set(reflect.ValueOf(value))
		return nil
	}
	return nil
}
