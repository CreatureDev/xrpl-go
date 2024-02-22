package transactions

type TxType string

const (
	AccountSetTx           TxType = "AccountSet"
	AccountDeleteTx        TxType = "AccountDelete"
	AMMBidTx               TxType = "AMMBid"
	AMMCreateTx            TxType = "AMMCreate"
	AMMDepositTx           TxType = "AMMDeposit"
	AMMVoteTx              TxType = "AMMVote"
	AMMWithdrawTx          TxType = "AMMWithdraw"
	CheckCancelTx          TxType = "CheckCancel"
	CheckCashTx            TxType = "CheckCash"
	CheckCreateTx          TxType = "CheckCreate"
	DepositPreauthTx       TxType = "DepositPreauth"
	EscrowCancelTx         TxType = "EscrowCancel"
	EscrowCreateTx         TxType = "EscrowCreate"
	EscrowFinishTx         TxType = "EscrowFinish"
	NFTokenAcceptOfferTx   TxType = "NFTokenAcceptOffer"
	NFTokenBurnTx          TxType = "NFTokenBurn"
	NFTokenCancelOfferTx   TxType = "NFTokenCancelOffer"
	NFTokenCreateOfferTx   TxType = "NFTokenCreateOffer"
	NFTokenMintTx          TxType = "NFTokenMint"
	OfferCreateTx          TxType = "OfferCreate"
	OfferCancelTx          TxType = "OfferCancel"
	PaymentTx              TxType = "Payment"
	PaymentChannelClaimTx  TxType = "PaymentChannelClaim"
	PaymentChannelCreateTx TxType = "PaymentChannelCreate"
	PaymentChannelFundTx   TxType = "PaymentChannelFund"
	SetRegularKeyTx        TxType = "SetRegularKey"
	SignerListSetTx        TxType = "SignerListSet"
	TrustSetTx             TxType = "TrustSet"
	TicketCreateTx         TxType = "TicketCreate"
	HashedTx               TxType = "HASH"   // TX stored as a string, rather than complete tx obj
	BinaryTx               TxType = "BINARY" // TX stored as a string, json tagged as 'tx_blob'
)

func GetTxTypeOfString(t string) TxType {
	switch TxType(t) {

	case AccountSetTx:
		return AccountSetTx
	case AccountDeleteTx:
		return AccountDeleteTx
	case AMMBidTx:
		return AMMBidTx
	case AMMCreateTx:
		return AMMCreateTx
	case AMMDepositTx:
		return AMMDepositTx
	case AMMVoteTx:
		return AMMVoteTx
	case AMMWithdrawTx:
		return AMMWithdrawTx
	case CheckCancelTx:
		return CheckCancelTx
	case CheckCashTx:
		return CheckCashTx
	case CheckCreateTx:
		return CheckCreateTx
	case DepositPreauthTx:
		return DepositPreauthTx
	case EscrowCancelTx:
		return EscrowCancelTx
	case EscrowCreateTx:
		return EscrowCreateTx
	case EscrowFinishTx:
		return EscrowFinishTx
	case NFTokenAcceptOfferTx:
		return NFTokenAcceptOfferTx
	case NFTokenBurnTx:
		return NFTokenBurnTx
	case NFTokenCancelOfferTx:
		return NFTokenCancelOfferTx
	case NFTokenCreateOfferTx:
		return NFTokenCreateOfferTx
	case NFTokenMintTx:
		return NFTokenMintTx
	case OfferCreateTx:
		return OfferCreateTx
	case OfferCancelTx:
		return OfferCancelTx
	case PaymentTx:
		return PaymentTx
	case PaymentChannelClaimTx:
		return PaymentChannelClaimTx
	case PaymentChannelCreateTx:
		return PaymentChannelCreateTx
	case PaymentChannelFundTx:
		return PaymentChannelFundTx
	case SetRegularKeyTx:
		return SetRegularKeyTx
	case SignerListSetTx:
		return SignerListSetTx
	case TrustSetTx:
		return TrustSetTx
	case TicketCreateTx:
		return TicketCreateTx
	case HashedTx:
		return HashedTx
	case BinaryTx:
		return BinaryTx
	default:
		return TxType("")
	}
}
