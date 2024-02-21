package keypairs

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	addresscodec "github.com/CreatureDev/xrpl-go/address-codec"
	binarycodec "github.com/CreatureDev/xrpl-go/binary-codec"
	"github.com/CreatureDev/xrpl-go/model/transactions"
	"github.com/CreatureDev/xrpl-go/model/transactions/types"
	"github.com/stretchr/testify/require"
)

func TestGenerateEncodeSeed(t *testing.T) {

	tt := []struct {
		description string
		entropy     string
		algorithm   addresscodec.CryptoAlgorithm
		expected    string
		expectedErr error
	}{
		{
			description: "Empty entropy should generate random seed (ED25519)",
			entropy:     "",
			algorithm:   addresscodec.ED25519,
			expected:    "sEdTjrdnJaPE2NNjmavQqXQdrf71NiH",
			expectedErr: nil,
		},
		{
			description: "Entropy defined and above family seed length (ED25519)",
			entropy:     "setPasswordOverLen16",
			algorithm:   addresscodec.ED25519,
			expected:    "sEdTuXdrgQobjDidph2oMDN36jGZX2U",
			expectedErr: nil,
		},
		{
			description: "Empty entropy should generate random seed (SECP256K1)",
			entropy:     "",
			algorithm:   addresscodec.SECP256K1,
			expected:    "sh3pdwcaoo7vt5rtrEZJ7a75LnDo3",
			expectedErr: nil,
		},
		{
			description: "Entropy defined and above family seed length (SECP256K1)",
			entropy:     "setPasswordOverLen16",
			algorithm:   addresscodec.SECP256K1,
			expected:    "shJYdazRN9dvWbGqCehzHcBKWBaFR",
			expectedErr: nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			if tc.entropy == "" {
				fb := bytes.NewBuffer([]byte("fakeRandomString"))
				tr := randomizer{
					fb,
				}
				r = tr
			}
			a, err := GenerateSeed(tc.entropy, tc.algorithm)

			if tc.expectedErr != nil {
				require.Zero(t, a)
				require.Error(t, err, tc.expectedErr.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expected, a)
			}
		})
	}
}

func TestDeriveKeypair(t *testing.T) {
	tt := []struct {
		description    string
		inputSeed      string
		inputValidator bool
		pubKey         string
		privKey        string
		expectedErr    error
	}{
		{
			description:    "Derive an ED25519 keypair",
			inputSeed:      "sEdTjrdnJaPE2NNjmavQqXQdrf71NiH",
			inputValidator: false,
			pubKey:         "ED4924A9045FE5ED8B22BAA7B6229A72A287CCF3EA287AADD3A032A24C0F008FA6",
			privKey:        "EDBB3ECA8985E1484FA6A28C4B30FB0042A2CC5DF3EC8DC37B5F3D126DDFD3CA14",
			expectedErr:    nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			priv, pub, err := DeriveKeypair(tc.inputSeed, tc.inputValidator)

			if tc.expectedErr != nil {
				require.Zero(t, pub)
				require.Zero(t, priv)
				require.Error(t, err, tc.expectedErr.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.pubKey, pub)
				require.Equal(t, tc.privKey, priv)
			}
		})
	}
}

func TestGetCryptoImplementation(t *testing.T) {
	tt := []struct {
		description string
		input       addresscodec.CryptoAlgorithm
		expected    CryptoImplementation
	}{
		{
			description: "Return ed25519 implementation - ED25519",
			input:       addresscodec.ED25519,
			expected:    &ed25519Alg{},
		},
		{
			description: "Not a valid crypto implementation",
			input:       addresscodec.Undefined,
			expected:    nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			actual := getCryptoImplementation(tc.input)
			require.Equal(t, tc.expected, actual)
		})
	}
}

func TestDeriveClassicAddress(t *testing.T) {
	tt := []struct {
		description string
		input       string
		expected    string
		expectedErr error
	}{
		{
			description: "Derive correct address from public key",
			input:       "ED731C39781B964904E1FEEFFC9F99442196BCB5F499105A79533E2D678CA7D3D2",
			expected:    "rhTCnDC7v1Jp7NAupzisv6ynWHD161Q9nV",
			expectedErr: nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			actual, err := DeriveClassicAddress(tc.input)
			if tc.expectedErr != nil {
				require.Zero(t, actual)
				require.Error(t, err, tc.expectedErr.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expected, actual)
			}
		})
	}
}

func TestSign(t *testing.T) {
	tt := []struct {
		description  string
		inputMsg     string
		inputPrivKey string
		expected     string
		expectedErr  error
	}{
		{
			description:  "Sign a message with a ED25519 key",
			inputMsg:     "hello world",
			inputPrivKey: "EDBB3ECA8985E1484FA6A28C4B30FB0042A2CC5DF3EC8DC37B5F3D126DDFD3CA14",
			expected:     "E83CAFEAF100793F0C6570D60C7447FF3A87E0DC0CAE9AD90EF0102860EC3BD1D20F432494021F3E19DAFF257A420CA64A49C283AB5AD00B6B0CEA1756151C01",
			expectedErr:  nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			actual, err := Sign([]byte(tc.inputMsg), tc.inputPrivKey)
			if tc.expectedErr != nil {
				require.Zero(t, actual)
				require.Error(t, err, tc.expectedErr.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expected, actual)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	tt := []struct {
		description string
		inputMsg    string
		inputPubKey string
		inputSig    string
		expected    bool
		expectedErr error
	}{
		{
			description: "Valid message with ED25519 key",
			inputMsg:    "test message",
			inputPubKey: "ED4924A9045FE5ED8B22BAA7B6229A72A287CCF3EA287AADD3A032A24C0F008FA6",
			inputSig:    "C001CB8A9883497518917DD16391930F4FEE39CEA76C846CFF4330BA44ED19DC4730056C2C6D7452873DE8120A5023C6807135C6329A89A13BA1D476FE8E7100",
			expected:    true,
			expectedErr: nil,
		},
	}

	for _, tc := range tt {
		t.Run(tc.description, func(t *testing.T) {
			actual, err := Validate([]byte(tc.inputMsg), tc.inputPubKey, tc.inputSig)
			if tc.expectedErr != nil {
				require.Zero(t, actual)
				require.Error(t, err, tc.expectedErr.Error())
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expected, actual)
			}
		})
	}
}

func TestTransaction(t *testing.T) {
	tt := []struct {
		Tx          transactions.Tx
		privateKey  string
		expectedSig string
		expectedEnc string
	}{
		{
			Tx: &transactions.Payment{
				BaseTx: transactions.BaseTx{
					Account:         types.Address("rNJWfdMZ4KM7sZAwY5MLfFfY3tDf77a7S5"),
					TransactionType: transactions.PaymentTx,
					Fee:             types.XRPCurrencyAmount(10),
					Sequence:        45537829,
					SigningPubKey:   "ED17F53B9BBBA35BCC8E2ED0DA078B5391E191A1193CA272727D035DA3FC60A39B",
					Flags:           types.SetFlag(0),
				},
				Amount:      types.XRPCurrencyAmount(100),
				Destination: types.Address("rMSNLbqJK1BuUsSbqUbq6KVr665vZMAiVo"),
			},
			privateKey:  "ED98EDA9342E29FDC0F8141E42E0B9470631A65B16BAC07FC7535B3E450E29C548",
			expectedSig: "2F35CEE92BDE5126FFEC7B210491709CE1D1E348F34DBC974A225FB956507150887717FAFA71589D4893E5048B85C153FD05ED192320F9C705B5D1274FCF7302",
			expectedEnc: "5354580012000022000000002402B6DA2561400000000000006468400000000000000A7321ED17F53B9BBBA35BCC8E2ED0DA078B5391E191A1193CA272727D035DA3FC60A39B811491E9028888C90F420E665AF6274041F1B7771B5F8314E0280C75CD9BDCB2B5A55BB8DF1C8B88006D886F",
		},
	}
	for _, tc := range tt {
		enc, err := binarycodec.EncodeForSigning(tc.Tx)
		require.NoError(t, err)
		require.Equal(t, tc.expectedEnc, strings.ToUpper(hex.EncodeToString(enc)))
		actual, err := Sign(enc, tc.privateKey)
		require.NoError(t, err)
		require.Equal(t, tc.expectedSig, actual)
	}
}
