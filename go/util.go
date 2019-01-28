package confidentiality

// zero a byte slice
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
