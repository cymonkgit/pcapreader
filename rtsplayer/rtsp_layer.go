package rtsplayer

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// RTP 전송 타입
type TransferType int

const (
	TransferProtocol_UDP = iota
	TransferProtocol_TCP
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
	Protocol          TransferType         // from SETUP
	Unicast           bool                 // from SETUP
	SessionId         int                  // from SETUP request
	SessionTimeoutSec int                  // from SETUP request
	ServerPort        string               // from SETUP request
	CilenttPort       string               // from SETUP request
	SSRC              string               // SSID. from SETUP reply

	lastReqMethod        RequestMethodType
	lastReqCSeq          int
	firstRtspPacketIndex int
	firstRtpPacketIndex  int
}

type RtspContextMap map[string]*RtspContext

func (c *RtspContext) GetBPFFilter() (filter string, err error) {
	// TCP
	if c.Protocol == TransferProtocol_TCP {
		// e.g "(src host 172.168.11.148 && src port 554) || (dst host 172.168.11.148 && dst port 554)"
		ip, port, er := GetIpPort(c.ServerAddress)
		if nil != er {
			err = er
			return
		}
		filter = fmt.Sprintf("(tcp && src host %v && src port %v) || (tcp && dst host %v && dst port %v)", ip, port, ip, port)
		return
	} else if c.Protocol == TransferProtocol_UDP {
		serverIp, rtspPort, er := GetIpPort(c.ServerAddress)
		if nil != er {
			err = er
			return
		}
		clientIp, _, er := GetIpPort(c.ClientAddress)
		if nil != er {
			err = er
			return
		}
		clientPorts := strings.Split(c.CilenttPort, "-")
		if len(clientPorts) != 2 {
			err = errors.New("invalid rtp receive port range value")
			return
		}
		filter = fmt.Sprintf("(tcp && src host %v && src port %v) || (tcp && dst host %v && dst port %v) || (udp && dst %v && portrange %v-%v)",
			serverIp, rtspPort, serverIp, rtspPort, clientIp, clientPorts[0], clientPorts[1])
		return
	} else {
		err = errors.New("invalid RTSP protocol type")
		return
	}
}

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
		fmt.Sprintln("transfer type:", c.Protocol),
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
	MsgField_Transport     = "transport"

	ContentType_SDP = "application/sdp"
)

func getAddress(ip, port string) string {
	return ip + ":" + port
}

func GetIpPort(addr string) (ip, port string, err error) {
	strs := strings.Split(addr, ":")
	if len(strs) != 2 {
		err = errors.New("invalid address")
		return
	}

	ip = strs[0]
	port = strings.ReplaceAll(strs[1], "(rtsp)", "")

	return
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

	rtspCtxMap := make(RtspContextMap)

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

type BytePacket struct {
	Index   int
	Payload []byte
	Delay   time.Duration
}

func DemuxRtsp(fileName string, ctx RtspContext) error {
	// Open up the pcap file for reading
	handle, err := pcap.OpenOffline(fileName)
	if err != nil {
		return err
	}
	defer handle.Close()

	// set BPF filter
	bpfFilter, err := ctx.GetBPFFilter()
	if nil != err {
		return err
	}
	err = handle.SetBPFFilter(bpfFilter)
	if nil != err {
		return err
	}

	// ctx.ClientAddress
	// handle.SetBPFFilter()

	return nil
}
