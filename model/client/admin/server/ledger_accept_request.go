package server

type LedgerAcceptRequest struct {
}

func (*LedgerAcceptRequest) Method() string {
	return "leder_accept"
}

func (*LedgerAcceptRequest) Validate() error {
	return nil
}
