package util

func U16be(u uint16, b []byte) {
	b[0] = byte(u >> 8)
	b[1] = byte(u)
}

func Beu16(b []byte) uint16 {
	u := uint16(b[0])<<8 | uint16(b[1])
	return u
}

func U32be(u uint32, b []byte) {
	b[0] = byte(u >> 24)
	b[1] = byte(u >> 16)
	b[2] = byte(u >> 8)
	b[3] = byte(u)
}

func Beu32(b []byte) uint32 {
	u := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return u
}
