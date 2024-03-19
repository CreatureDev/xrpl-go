package types

const (
	// Transaction flags
	FtfBurnable            Flag = 0x1
	FtfOnlyXrp                  = 0x2
	FtfTransferable             = 0x8
	FtfNoDirectRipple           = 0x10000
	FtfPartialPayment           = 0x20000
	FtfLimitQuality             = 0x40000
	FtfRequireDestTag           = 0x10000
	FtfOptionalDestTag          = 0x20000
	FtfRequireAuth              = 0x40000
	FtfOptionalAuth             = 0x80000
	FtfDisallowXRP              = 0x100000
	FtfAllowXRP                 = 0x200000
	FtfLPToken                  = 0x10000
	FtfTwoAsset                 = 0x100000
	FtfTwoAssetIfEmpty          = 0x800000
	FtfSingleAsset              = 0x80000
	FtfOneAssetLPToken          = 0x200000
	FtfLimitLPToken             = 0x400000
	FtfWithdrawAll              = 0x20000
	FtfOneAssetWithdrawAll      = 0x40000

	// Account Set Flags
	FasfAccountTxnID                 = 5
	FasfAllowTrustLineClawback       = 16
	FasfAuthorizedNFTokenMinter      = 10
	FasfDefaultRipple                = 8
	FasfDepositAuth                  = 9
	FasfDisableMaster                = 4
	FasfDisallowIncomingCheck        = 13
	FasfDisallowIncomingNFTokenOffer = 12
	FasfDisallowIncomingPayChan      = 14
	FasfDisallowIncomingTrustline    = 15
	FasfDisallowXRP                  = 3
	FasfGlobalFreeze                 = 7
	FasfNoFreeze                     = 6
	FasfRequireAuth                  = 2
	FasfRequireDest                  = 1
)

// FlagsI is an interface for types that can be converted to a uint.
type FlagsI interface {
	ToUint() uint32
}

type Flag uint32

func (f *Flag) ToUint() uint32 {
	return uint32(*f)
}

// SetFlag is a helper function that allocates a new uint value
// to store v and returns a pointer to it.
func SetFlag(v uint32) *Flag {
	p := new(uint32)
	*p = v
	return (*Flag)(p)
}

func NewFlag() *Flag {
	return SetFlag(0)
}

func (f *Flag) SetFlag(v Flag) *Flag {
	*f = *f | v
	return f
}

func (f *Flag) ClearFlag(v Flag) *Flag {
	*f = *f &^ v
	return f
}

func (f *Flag) ToggleFlag(v Flag) *Flag {
	*f = *f ^ v
	return f
}

func (f *Flag) HasFlag(v Flag) bool {
	if *f&v != 0 {
		return true
	}
	return false
}
