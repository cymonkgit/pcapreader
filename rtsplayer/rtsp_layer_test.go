package rtsplayer

import (
	"fmt"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func Test_ParseOptions(t *testing.T) {
	s := "Authorization: Digest username=\"gu\\\"e\\\"st\", realm=\"RealHUB Streaming Server\", nonce=\"c6bcddac12782de4b0b1f357e3932f37\", uri=\"rtsp://172.168.11.148:554/UkVDLTEwOTgtueYtvvbBpA==\", response=\"f3ec885c099e83b80c47773353d2c29c\""

	k, v, e := parseMessage(s)
	if nil != e {
		t.Fatal()
	}
	fmt.Println("key:", k)
	fmt.Printf("value:'%v'", v)

	digest, e := parseAuthorization(v)
	// k, v, e := getFirstKeyAndValue(s)
	// if nil != e {
	// 	t.Fatal(e)
	// }

	// fmt.Println("key", k, "value", v)
	if nil != e {
		t.Fatal()
	}

	fmt.Println(digest)
}

// filter test
func Test_Filter(t *testing.T) {
	fileName := "C:/temp/1098-packet.pcapng"
	handle, err := pcap.OpenOffline(fileName)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()

	// err = handle.SetBPFFilter("src host 172.168.11.33 || src host 172.168.11.148")
	// err = handle.SetBPFFilter("(tcp src host 172.168.11.148 && tcp src port 554) || (dst host 172.168.11.148 && dst port 554)")
	err = handle.SetBPFFilter("(tcp && src host 172.168.11.148 && src port 554) || (tcp && dst host 172.168.11.148 && dst port 554)")
	if nil != err {
		t.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println(packet)
	}

}
