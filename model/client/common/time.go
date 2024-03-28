package common

import "time"

const RIPPLE_EPOCH = 946684800

func CurrentRippleTime() uint {
	now := time.Now()
	return uint(now.Unix() - RIPPLE_EPOCH)
}
