package confidentiality

import (
	"crypto/rand"
)

// randomReader is our random source, can be overwritten for tests
var randomReader = rand.Reader
