package casket

import "time"

// UnixNowForTest exposes the current unix timestamp for use in test fixtures.
func UnixNowForTest() int64 {
	return time.Now().Unix()
}
