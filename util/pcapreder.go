package util

import (
	"errors"
	"strconv"
	"strings"
)

const (
	LayerType_RtspRequest = 2001 + iota
	LayerType_RtspResponse
	LayerType_Rtp
	LayerType_Rtcp
	LayerType_Sdp
)

func Port(address string) (port int, err error) {
	strs := strings.Split(address, ":")
	if len(strs) != 2 {
		err = errors.New("invalid address:port")
		return
	}

	return strconv.Atoi(strs[1])
}
