//go:build unit
// +build unit

package binarycodec

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xyield/xrpl-go/binary-codec/definitions"
)

// Binary serializations of valid transactions json
var (
	Tx1 = "120007220008000024001ABED82A2380BF2C2019001ABED764D55920AC9391400000000000000000000000000055534400000000000A20B3C85F482532A9578DBB3950B85CA06594D165400000037E11D60068400000000000000A732103EE83BB432547885C219634A1BC407A9DB0474145D69737D09CCDC63E1DEE7FE3744630440220143759437C04F7B61F012563AFE90D8DAFC46E86035E1D965A9CED282C97D4CE02204CFD241E86F17E011298FC1A39B63386C74306A5DE047E213B0F29EFA4571C2C8114DD76483FACDEE26E60D8A586BB58D09F27045C46"
	Tx2 = "1200022280000000240000000120190000000B68400000000000277573210268D79CD579D077750740FA18A2370B7C2018B2714ECE70BA65C38D223E79BC9C74473045022100F06FB54049D6D50142E5CF2E2AC21946AF305A13E2A2D4BA881B36484DD01A540220311557EC8BEF536D729605A4CB4D4DC51B1E37C06C93434DD5B7651E1E2E28BF811452C7F01AD13B3CA9C1D133FA8F3482D2EF08FA7D82145A380FBD236B6A1CD14B939AD21101E5B6B6FFA2F9EA7D0F04C4D46544659A2D58525043686174E1F1"
	Tx3 = "1200002200000000240000034A201B009717BE61400000000098968068400000000000000C69D4564B964A845AC0000000000000000000000000555344000000000069D33B18D53385F8A3185516C2EDA5DEDB8AC5C673210379F17CFA0FFD7518181594BE69FE9A10471D6DE1F4055C6D2746AFD6CF89889E74473045022100D55ED1953F860ADC1BC5CD993ABB927F48156ACA31C64737865F4F4FF6D015A80220630704D2BD09C8E99F26090C25F11B28F5D96A1350454402C2CED92B39FFDBAF811469D33B18D53385F8A3185516C2EDA5DEDB8AC5C6831469D33B18D53385F8A3185516C2EDA5DEDB8AC5C6F9EA7C06636C69656E747D077274312E312E31E1F1011201F3B1997562FD742B54D4EBDEA1D6AEA3D4906B8F100000000000000000000000000000000000000000FF014B4E9C06F24296074F7BC48F92A97916C6DC5EA901DD39C650A96EDA48334E70CC4A85B8B2E8502CD310000000000000000000000000000000000000000000"
)

func TestCreateFieldInstanceMapFromJson(t *testing.T) {

	tt := []struct {
		description string
		input       map[string]interface{}
		output      map[definitions.FieldInstance]interface{}
		expectedErr error
	}{
		{
			description: "convert valid Json",
			input: map[string]interface{}{
				"Fee":           "10",
				"Flags":         524288,
				"OfferSequence": 1752791,
				"TakerGets":     "150000000000",
			},
			output: map[definitions.FieldInstance]interface{}{
				getFieldInstance(t, "Fee"):           "10",
				getFieldInstance(t, "Flags"):         524288,
				getFieldInstance(t, "OfferSequence"): 1752791,
				getFieldInstance(t, "TakerGets"):     "150000000000",
			},
			expectedErr: nil,
		},
		{
			description: "not found error",
			input: map[string]interface{}{
				"IncorrectField": 89,
				"Flags":          525288,
				"OfferSequence":  1752791,
			},
			output:      nil,
			expectedErr: errors.New("FieldName IncorrectField not found"),
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {

			got, err := createFieldInstanceMapFromJson(tc.input)
			if tc.expectedErr != nil {
				assert.EqualError(t, err, tc.expectedErr.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.output, got)
			}
		})
	}

}

func getFieldInstance(t *testing.T, fieldName string) definitions.FieldInstance {
	t.Helper()
	fi, err := definitions.Get().GetFieldInstanceByFieldName(fieldName)
	if err != nil {
		t.Fatalf("FieldInstance with FieldName %v", fieldName)
	}
	return *fi
}

func TestGetSortedKeys(t *testing.T) {
	tt := []struct {
		input  map[definitions.FieldInstance]interface{}
		output []definitions.FieldInstance
	}{
		{
			input: map[definitions.FieldInstance]interface{}{
				getFieldInstance(t, "IndexNext"):       5100000,
				getFieldInstance(t, "SourceTag"):       1232,
				getFieldInstance(t, "LedgerEntryType"): 1,
			},
			output: []definitions.FieldInstance{
				getFieldInstance(t, "LedgerEntryType"),
				getFieldInstance(t, "SourceTag"),
				getFieldInstance(t, "IndexNext"),
			},
		},
		{
			input: map[definitions.FieldInstance]interface{}{
				getFieldInstance(t, "Account"):      "rMBzp8CgpE441cp5PVyA9rpVV7oT8hP3ys",
				getFieldInstance(t, "TransferRate"): 4234,
				getFieldInstance(t, "Expiration"):   23,
			},
			output: []definitions.FieldInstance{
				getFieldInstance(t, "Expiration"),
				getFieldInstance(t, "TransferRate"),
				getFieldInstance(t, "Account"),
			},
		},
	}

	for i, tc := range tt {
		t.Run(fmt.Sprintf("Test %v", i), func(t *testing.T) {
			assert.Equal(t, tc.output, getSortedKeys(tc.input))
		})
	}
}
func TestEncode(t *testing.T) {
	tt := []struct {
		description string
		fromTx      string
		input       map[string]any
		output      string
		expectedErr error
	}{
		// {
		// 	description: "successfully serialized signed transaction 1",
		// 	input: map[string]any{
		// 		"Account":       "rMBzp8CgpE441cp5PVyA9rpVV7oT8hP3ys",
		// 		"Expiration":    595640108,
		// 		"Fee":           "10",
		// 		"Flags":         524288,
		// 		"OfferSequence": 1752791,
		// 		"Sequence":      1752792,
		// 		"SigningPubKey": "03EE83BB432547885C219634A1BC407A9DB0474145D69737D09CCDC63E1DEE7FE3",
		// 		"TakerGets":     "15000000000",
		// 		"TakerPays": map[string]any{
		// 			"currency": "USD",
		// 			"issuer":   "rvYAfWj5gh67oV6fW32ZzP3Aw4Eubs59B",
		// 			"value":    "7072.8",
		// 		},
		// 		"TransactionType": "OfferCreate",
		// 		"TxnSignature":    "30440220143759437C04F7B61F012563AFE90D8DAFC46E86035E1D965A9CED282C97D4CE02204CFD241E86F17E011298FC1A39B63386C74306A5DE047E213B0F29EFA4571C2C",
		// 		"hash":            "73734B611DDA23D3F5F62E20A173B78AB8406AC5015094DA53F53D39B9EDB06C",
		// 	},
		// 	output:      "120007220008000024001ABED82A2380BF2C2019001ABED764D55920AC9391400000000000000000000000000055534400000000000A20B3C85F482532A9578DBB3950B85CA06594D165400000037E11D60068400000000000000A732103EE83BB432547885C219634A1BC407A9DB0474145D69737D09CCDC63E1DEE7FE3744630440220143759437C04F7B61F012563AFE90D8DAFC46E86035E1D965A9CED282C97D4CE02204CFD241E86F17E011298FC1A39B63386C74306A5DE047E213B0F29EFA4571C2C8114DD76483FACDEE26E60D8A586BB58D09F27045C46",
		// 	expectedErr: nil,
		// },
		// {
		// 	description: "successfully serialized signed transaction 2",
		// 	input: map[string]any{
		// 		"TransactionType": "EscrowFinish",
		// 		"Flags": 2147483648,
		// 		"Sequence": 1,
		// 		"OfferSequence": 11,
		// 		"Fee": "10101",
		// 		"SigningPubKey": "0268D79CD579D077750740FA18A2370B7C2018B2714ECE70BA65C38D223E79BC9C",
		// 		"TxnSignature": "3045022100F06FB54049D6D50142E5CF2E2AC21946AF305A13E2A2D4BA881B36484DD01A540220311557EC8BEF536D729605A4CB4D4DC51B1E37C06C93434DD5B7651E1E2E28BF",
		// 		"Account": "r3Y6vCE8XqfZmYBRngy22uFYkmz3y9eCRA",
		// 		"Owner": "r9NpyVfLfUG8hatuCCHKzosyDtKnBdsEN3",
		// 		"Memos": [
		// 			{
		// 				"Memo": {
		// 					"MemoData": "04C4D46544659A2D58525043686174"
		// 				}
		// 			}
		// 		]
		// 	},
		// 	output: "1200022280000000240000000120190000000B68400000000000277573210268D79CD579D077750740FA18A2370B7C2018B2714ECE70BA65C38D223E79BC9C74473045022100F06FB54049D6D50142E5CF2E2AC21946AF305A13E2A2D4BA881B36484DD01A540220311557EC8BEF536D729605A4CB4D4DC51B1E37C06C93434DD5B7651E1E2E28BF811452C7F01AD13B3CA9C1D133FA8F3482D2EF08FA7D82145A380FBD236B6A1CD14B939AD21101E5B6B6FFA2F9EA7D0F04C4D46544659A2D58525043686174E1F1",
		// 	expectedErr: nil,
		// },
		// {
		// 	description: "successfully serialized signed transaction 3",
		// 	input: map[string]any{
		// 		{
		// 			"Account": "rweYz56rfmQ98cAdRaeTxQS9wVMGnrdsFp",
		// 			"Amount": "10000000",
		// 			"Destination": "rweYz56rfmQ98cAdRaeTxQS9wVMGnrdsFp",
		// 			"Fee": "12",
		// 			"Flags": 0,
		// 			"LastLedgerSequence": 9902014,
		// 			"Memos": [
		// 			  {
		// 				"Memo": {
		// 				  "MemoData": "7274312E312E31",
		// 				  "MemoType": "636C69656E74"
		// 				}
		// 			  }
		// 			],
		// 			"Paths": [
		// 			  [
		// 				{
		// 				  "account": "rPDXxSZcuVL3ZWoyU82bcde3zwvmShkRyF",
		// 				  "type": 1,
		// 				  "type_hex": "0000000000000001"
		// 				},
		// 				{
		// 				  "currency": "XRP",
		// 				  "type": 16,
		// 				  "type_hex": "0000000000000010"
		// 				}
		// 			  ],
		// 			  [
		// 				{
		// 				  "account": "rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpn",
		// 				  "type": 1,
		// 				  "type_hex": "0000000000000001"
		// 				},
		// 				{
		// 				  "account": "rMwjYedjc7qqtKYVLiAccJSmCwih4LnE2q",
		// 				  "type": 1,
		// 				  "type_hex": "0000000000000001"
		// 				},
		// 				{
		// 				  "currency": "XRP",
		// 				  "type": 16,
		// 				  "type_hex": "0000000000000010"
		// 				}
		// 			  ]
		// 			],
		// 			"SendMax": {
		// 			  "currency": "USD",
		// 			  "issuer": "rweYz56rfmQ98cAdRaeTxQS9wVMGnrdsFp",
		// 			  "value": "0.6275558355"
		// 			},
		// 			"Sequence": 842,
		// 			"SigningPubKey": "0379F17CFA0FFD7518181594BE69FE9A10471D6DE1F4055C6D2746AFD6CF89889E",
		// 			"TransactionType": "Payment",
		// 			"TxnSignature": "3045022100D55ED1953F860ADC1BC5CD993ABB927F48156ACA31C64737865F4F4FF6D015A80220630704D2BD09C8E99F26090C25F11B28F5D96A1350454402C2CED92B39FFDBAF",
		// 			"hash": "B521424226FC100A2A802FE20476A5F8426FD3F720176DC5CCCE0D75738CC208"
		// 		  }
		// 	},
		// 	output: "1200002200000000240000034A201B009717BE61400000000098968068400000000000000C69D4564B964A845AC0000000000000000000000000555344000000000069D33B18D53385F8A3185516C2EDA5DEDB8AC5C673210379F17CFA0FFD7518181594BE69FE9A10471D6DE1F4055C6D2746AFD6CF89889E74473045022100D55ED1953F860ADC1BC5CD993ABB927F48156ACA31C64737865F4F4FF6D015A80220630704D2BD09C8E99F26090C25F11B28F5D96A1350454402C2CED92B39FFDBAF811469D33B18D53385F8A3185516C2EDA5DEDB8AC5C6831469D33B18D53385F8A3185516C2EDA5DEDB8AC5C6F9EA7C06636C69656E747D077274312E312E31E1F1011201F3B1997562FD742B54D4EBDEA1D6AEA3D4906B8F100000000000000000000000000000000000000000FF014B4E9C06F24296074F7BC48F92A97916C6DC5EA901DD39C650A96EDA48334E70CC4A85B8B2E8502CD310000000000000000000000000000000000000000000",
		// 	expectedErr: nil,
		// },
		// {
		// 	description: "serialize TransactionType from successfully signed tx 1",
		// 	fromTx:      Tx1,
		// 	input:       map[string]any{"TransactionType": "OfferCreate"},
		// 	output:      "120007",
		// 	expectedErr: nil,
		// },
		{
			description: "serialize Flags from successfully signed tx 1",
			fromTx:      Tx1,
			input:       map[string]any{"Flags": 524288},
			output:      "2200080000",
			expectedErr: nil,
		},
		{
			description: "serialize Sequence from successfully signed tx 1",
			fromTx:      Tx1,
			input:       map[string]any{"Sequence": 1752792},
			output:      "24001abed8",
			expectedErr: nil,
		},
		{
			description: "serialize Expiration from successfully signed tx 1",
			fromTx:      Tx1,
			input:       map[string]any{"Expiration": 595640108},
			output:      "2a2380bf2c",
			expectedErr: nil,
		},
		{
			description: "serialize OfferSequence from successfully signed tx 1",
			fromTx:      Tx1,
			input:       map[string]any{"OfferSequence": 1752791},
			output:      "2019001abed7",
			expectedErr: nil,
		},
		// {
		// 	description: "serialize hash from successfully signed tx 1",
		// 	fromTx:      Tx1,
		// 	input:       map[string]any{"hash": "73734B611DDA23D3F5F62E20A173B78AB8406AC5015094DA53F53D39B9EDB06C"},
		// 	output:      "",
		// 	expectedErr: nil,
		// },
		// {
		// 	description: "serialize TakerPays from successfully signed tx 1",
		// 	fromTx:      Tx1,
		// 	input: map[string]any{
		// 		"currency": "USD",
		// 		"issuer":   "rvYAfWj5gh67oV6fW32ZzP3Aw4Eubs59B",
		// 		"value":    "7072.8",
		// 	},
		// 	output:      "",
		// 	expectedErr: nil,
		// },
		// {
		// 	description: "serialize TakerGets from successfully signed tx 1",
		// 	fromTx:      Tx1,
		// 	input:       map[string]any{"TakerGets": "15000000000"},
		// 	output:      "",
		// 	expectedErr: nil,
		// },
		// {
		// 	description: "serialize Fee from successfully signed tx 1",
		// 	fromTx:      Tx1,
		// 	input:       map[string]any{"Fee": "10"},
		// 	output:      "",
		// 	expectedErr: nil,
		// },
		// {
		// 	description: "serialize SigningPubKey from successfully signed tx 1",
		// 	fromTx:      Tx1,
		// 	input:       map[string]any{"SigningPubKey": "03EE83BB432547885C219634A1BC407A9DB0474145D69737D09CCDC63E1DEE7FE3"},
		// 	output:      "",
		// 	expectedErr: nil,
		// },
		// {
		// 	description: "serialize TxnSignature from successfully signed tx 1",
		// 	fromTx:      Tx1,
		// 	input:       map[string]any{"TxnSignature": "30440220143759437C04F7B61F012563AFE90D8DAFC46E86035E1D965A9CED282C97D4CE02204CFD241E86F17E011298FC1A39B63386C74306A5DE047E213B0F29EFA4571C2C"},
		// 	output:      "",
		// 	expectedErr: nil,
		// },
		// {
		// 	description: "serialize Account from successfully signed tx 1",
		// 	fromTx:      Tx1,
		// 	input:       map[string]any{"Account": "rMBzp8CgpE441cp5PVyA9rpVV7oT8hP3ys"},
		// 	output:      "",
		// 	expectedErr: nil,
		// },
		{
			description: "serialize Flags from successfully signed tx 2",
			fromTx:      Tx2,
			input:       map[string]any{"Flags": 2147483648},
			output:      "2280000000",
			expectedErr: nil,
		},
		{
			description: "serialize Sequence from successfully signed tx 2",
			fromTx:      Tx2,
			input:       map[string]any{"Sequence": 1},
			output:      "2400000001",
			expectedErr: nil,
		},
		{
			description: "serialize OfferSequence from successfully signed tx 2",
			fromTx:      Tx2,
			input:       map[string]any{"OfferSequence": 11},
			output:      "20190000000b",
			expectedErr: nil,
		},
		{
			description: "serialize Flags from successfully signed tx 3",
			fromTx:      Tx3,
			input:       map[string]any{"Flags": 0},
			output:      "2200000000",
			expectedErr: nil,
		},
		{
			description: "serialize Sequence from successfully signed tx 3",
			fromTx:      Tx3,
			input:       map[string]any{"Sequence": 842},
			output:      "240000034a",
			expectedErr: nil,
		},
		{
			description: "serialize LastLedgerSequence from successfully signed tx 3",
			fromTx:      Tx3,
			input:       map[string]any{"LastLedgerSequence": 9902014},
			output:      "201b009717be",
			expectedErr: nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			got, err := Encode(tc.input)

			if tc.expectedErr != nil {
				assert.EqualError(t, err, tc.expectedErr.Error())
				assert.Empty(t, got)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.output, got)
			}

			// checks if serialized elements from example transactions Json are present in full transaction binary result
			switch tc.fromTx {
			case Tx1:
				assert.Contains(t, Tx1, strings.ToUpper(got))
			case Tx2:
				assert.Contains(t, Tx2, strings.ToUpper(got))
			default:
				assert.Contains(t, Tx3, strings.ToUpper(got))
			}
		})
	}

}