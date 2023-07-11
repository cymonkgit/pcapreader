package rtsplayer

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// RTP 전송 타입
type TransferType int

const (
	TransferType_UDP = iota
	TransferType_TCP
)

type DigestAuthorization struct {
	User     string
	Realm    string
	Nonce    string
	Uri      string
	Response string

	Authorized bool
}

type RtspContext struct {
	ClientAddress     string               // from ethernet/ip packet layer
	ServerAddress     string               // from ethernet/ip packet layer
	Url               string               // from OPTIONS
	UserAgent         string               // from OPTIONS, DESCRIBE ...
	SupportedMethod   []RequestMethodType  // from OPTIONS
	Auth              *DigestAuthorization // from DESCRIBE
	Accept            string               // from DESCRIBE
	TransferType      TransferType         // from SETUP
	SessionId         int32                // from SETUP request
	SessionTimeoutSec int                  // from SETUP request
	UdpServerPort     string               // from SETUP request
	UdpCilenttPort    string               // from SETUP request
	SSRC              string               // SSID. from SETUP reply

	lastReqMethod RequestMethodType
	lastReqCSeq   int
}

type RtspContextMap map[string]*RtspContext

func (c *RtspContext) String() string {
	getSupported := func(SupportedMethod []RequestMethodType) (support string) {
		for i, method := range SupportedMethod {
			if i != 0 {
				support += ", "
			}
			support += getMethodTypeText(method)
		}
		return
	}
	strs := []string{
		fmt.Sprintln("client address:", c.ClientAddress),
		fmt.Sprintln("server address:", c.ServerAddress),
		fmt.Sprintln("url:", c.Url),
		fmt.Sprintln("user agent:", c.UserAgent),
		fmt.Sprintln("supported:", getSupported(c.SupportedMethod)),
		fmt.Sprintln("accept:", c.Accept),
		fmt.Sprintln("transfer type:", c.TransferType),
		fmt.Sprintln("session id:", c.SessionId),
		fmt.Sprintln("session timeout:", c.SessionTimeoutSec),
		fmt.Sprintln("ssrc:", c.SSRC),
	}
	if nil != c.Auth {
		strs = append(strs, fmt.Sprintf("authority: authorized(%v), username(%v), realm(%v) ...", c.Auth.Authorized, c.Auth.User, c.Auth.Realm))
	} else {
		strs = append(strs, fmt.Sprintln("authority: not use"))
	}

	return strings.Join(strs[:], "")
}

// const (
// 	MsgFieldType_UserAgent = iota
// 	MsgFieldType_Authorization
// 	MsgFieldType_Accept
// 	MsgFieldType_Public
// 	MsgFieldType_ContentBase
// 	MsgFieldType_ContentType
// 	MsgFieldType_Range
// 	MsgFieldType_Session
// 	MsgEifldType_CSeq
// )

// general messages
const (
	MsgField_UserAgent     = "user-agent"
	MsgField_Authorization = "authorization"
	MsgField_Accept        = "accept"
	MsgField_Public        = "public"
	MsgField_ContentBase   = "content-base"
	MsgField_ContentType   = "content-type"
	MsgField_Range         = "range"
	MsgField_Session       = "session"
	MsgField_CSeq          = "cseq"

	ContentType_SDP = "application/sdp"
)

func getAddress(ip, port string) string {
	return ip + ":" + port
}

func getRtspContextId(serverIp, serverPort, clientIp, clientPort string) string {
	return getAddress(serverIp, serverPort) + "-" + getAddress(clientIp, clientPort)
}

func Probe(fileName string) (*RtspContextMap, error) {
	// Open up the pcap file for reading
	handle, err := pcap.OpenOffline(fileName)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	rtspCtxMap := make(RtspContextMap, 0)

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer == nil {
			continue
		}

		ethPacket, _ := ethLayer.(*layers.Ethernet)
		if nil == ethPacket {
			continue
		}
		// Extract and print the IP layer
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		if err = ProbeRequest(&packet, ethPacket, &ipLayer, &rtspCtxMap); nil == err {
			continue
		}
		if err = ProbeResponse(&packet, ethPacket, &ipLayer, &rtspCtxMap); nil == err {
			continue
		}
		// if err = ProbeResponse()
	}

	return &rtspCtxMap, nil
}

func parseMessage(option string) (key, val string, err error) {
	index := strings.Index(option, ":")
	if index < 0 || index >= len(option) {
		err = errors.New("invalid request option string")
		return
	}

	key = option[0:index]
	val = strings.Trim(option[index+1:], " \r\n")

	return
}
