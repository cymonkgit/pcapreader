package rtp

import "errors"

// RFC 3550 5.1
/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |V=2|P|X|  CC   |M|     PT      |       sequence number         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           timestamp                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           synchronization source (SSRC) identifier            |
   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
   |            contributing source (CSRC) identifiers             |
   |                             ....                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type RTPHeader struct {
	Version        uint8
	Padding        uint8
	Extension      uint8
	CSRCCount      uint8
	Marker         uint8
	PayloadType    uint8
	SequenceNumber uint16
	Timestamp      uint32
	SSRC           uint32
	CSRCS          []uint32
}

func u16be(u uint16, b []byte) {
	b[0] = byte(u >> 8)
	b[1] = byte(u)
}

func beu16(b []byte) uint16 {
	u := uint16(b[0])<<8 | uint16(b[1])
	return u
}

func u32be(u uint32, b []byte) {
	b[0] = byte(u >> 24)
	b[1] = byte(u >> 16)
	b[2] = byte(u >> 8)
	b[3] = byte(u)
}

func beu32(b []byte) uint32 {
	u := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return u
}

func (h *RTPHeader) calcHeaderLen() int {
	return 12 + len(h.CSRCS)*4
}

func (h RTPHeader) Marshal(b []byte) (marshalLen int, err error) {
	l := h.calcHeaderLen()
	if len(b) < l {
		err = errors.New("invalid length of byte buffer")
		return
	}
	if int(h.CSRCCount) > 0x0f {
		err = errors.New("invalid csrc")
		return
	}
	if int(h.CSRCCount) != len(h.CSRCS) {
		err = errors.New("csrc count mismatch")
		return
	}
	b[0] = h.Version<<6 | h.Padding<<5 | h.Extension<<4 | h.CSRCCount
	b[1] = h.Marker<<7 | h.PayloadType

	u16be(h.SequenceNumber, b[2:])
	u32be(h.Timestamp, b[4:])
	u32be(h.SSRC, b[8:])
	offset := 12
	for _, csrc := range h.CSRCS {
		u32be(csrc, b[offset:])
		offset += 4
	}
	marshalLen = l

	return
}

func (h *RTPHeader) Unmarshal(b []byte) (unmarshalLen int, err error) {
	if len(b) < 12 {
		err = errors.New("not enough data")
		return
	}

	val := b[0]
	h.Version = val >> 6
	h.Padding = (val & 0x20) >> 5
	h.Extension = (val & 0x10) >> 4
	h.CSRCCount = val & 0x0f

	if len(b) < int(12+(h.CSRCCount*4)) {
		err = errors.New("invalid data length")
		return
	}

	val = b[1]
	h.Marker = val & 0x10 >> 7
	h.PayloadType = val & 0x3f

	h.SequenceNumber = beu16(b[2:])
	h.Timestamp = beu32(b[4:])
	h.SSRC = beu32(b[8:])

	offset := 12
	if h.CSRCCount > 0 {
		h.CSRCS = make([]uint32, h.CSRCCount)
		for offset < len(b) {
			h.CSRCS = append(h.CSRCS, beu32(b[offset:]))
			offset += 4
		}
	}

	unmarshalLen = offset

	return
}

type RtpPacket struct {
	Header RTPHeader
	Data   []byte
}

func (pkt RtpPacket) Marshal() (data []byte, err error) {
	data = make([]byte, pkt.Header.calcHeaderLen()+len(pkt.Data))

	l, err := pkt.Header.Marshal(data)
	if nil != err {
		return
	}
	copy(data[l:], pkt.Data)

	return
}

func (pkt *RtpPacket) Unmarshal(b []byte) (unmarshalLen int, err error) {
	unmarshalLen, err = pkt.Header.Unmarshal(b)
	if nil != err {
		return
	}

	pkt.Data = b[unmarshalLen:]
	return
}
