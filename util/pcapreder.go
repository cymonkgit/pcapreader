package util

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"unicode"
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

func GetKeyAndValue(text string) (key, val string, err error) {
	index := strings.Index(text, "=")
	if index < 0 || index >= len(text) {
		err = errors.New("invalid key and value string")
		return
	}

	key = text[0:index]
	if !IsAlphanumeric(key) {
		err = errors.New("key is not letter")
		return
	}
	val = strings.Trim(text[index+1:], " ")
	return
}

func IsAlphanumeric(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) {
			return false
		}
	}
	return true
}

func GetKeyAndValueSet(s string) (kvset map[string]string, err error) {
	texts := strings.Split(s, ",")
	if len(texts) > 0 {
		kvset = make(map[string]string)
	}
	for _, text := range texts {
		if key, val, er := GetKeyAndValue(strings.Trim(text, " ")); nil == er {
			kvset[key] = val
		} else {
			err = er
			return
		}
	}

	return
}

func SplitBytesToStringBlocks(data []byte) []string {
	str := string(data)
	bodies := strings.Split(str, "\r\n\r\n")
	if len(bodies) < 1 {
		return nil
	}

	return bodies
}

func SplitByteIndices(data []byte, splitter string) []int {
	ret := []int{}

	startIndex := 0
	for {
		index := bytes.Index(data[startIndex:], []byte(splitter))
		if index > 0 {
			ret = append(ret, index+startIndex)
			startIndex += index + len(splitter)
		} else {
			break
		}
	}

	return ret
}
