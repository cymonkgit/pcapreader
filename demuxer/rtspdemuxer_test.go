package demuxer

import (
	"fmt"
	"testing"
	"time"

	"github.com/cymonkgit/pcapreader/rtsplayer"
)

func Test_Demuxer(t *testing.T) {
	dmx, err := open("D:/data/goryoung.pcapng", rtsplayer.TransferProtocol_TCP, "192.168.22.16:8554", "192.168.15.17:53306", "", time.Unix(0, 1695098574169698000))
	if nil != err {
		t.Fatal(err)
	}

	idx := 0
	for {
		pkt, err := dmx.ReadPacket()
		if nil != err {
			break
		}

		fmt.Println("packet time:", pkt.Time.String())

		if idx != 2 {
			fmt.Println("idx:", idx, ", hex:", fmt.Sprintf("% X", pkt.Payload[:16]))
		} else {
			start := 0
			for {
				if start >= len(pkt.Payload) || start+16 >= len(pkt.Payload) {
					break
				}
				fmt.Printf("% X\n", pkt.Payload[start:start+16])
				start += 16
			}
		}
		idx++
	}
}
