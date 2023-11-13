package demuxer

import (
	"fmt"
	"testing"
	"time"

	rtsplayer "github.com/cymonkgit/pcapreader/layers/rtsp"
)

func Test_Demuxer(t *testing.T) {
	dmx, err := open("C:/temp/goryung.pcapng", rtsplayer.TransferProtocol_TCP, "192.168.22.16:8554", "192.168.15.17:53306", "", time.Unix(0, 1695098574169698000))
	// dmx, err := open("D:/data/goryoung.pcapng", rtsplayer.TransferProtocol_TCP, "192.168.22.16:8554", "192.168.15.17:53306", "", time.Unix(0, 1695098574169698000))
	if nil != err {
		t.Fatal(err)
	}

	start := time.Now()
	idx := 0
	remains := make([]byte, 0)
	frameCount := 0
	for {
		rlen := len(remains)
		pkt, err := dmx.ReadPacket(&remains, idx)
		if nil != err || pkt == nil {
			break
		}

		ils := pkt.ILFI

		desc := ""
		for _, il := range ils {
			desc += il.GetText() + ", "
			if il.Marker != 0 {
				frameCount++
			}
		}

		fmt.Println("packet time:", pkt.Time.String(), ", length:", len(pkt.Payload), "captureLen:", pkt.CaptureLength, ", remainer:", rlen, desc)

		// if idx != 2 && idx != 1 {
		dispLen := 16
		if len(pkt.Payload) < dispLen {
			dispLen = len(pkt.Payload)
		}
		fmt.Println("idx:", idx, ", hex:", fmt.Sprintf("% X", pkt.Payload[:dispLen]))
		idx++
		// } else {
		// 	start := 0
		// 	sz := len(pkt.Payload)
		// 	cnt := sz / 16
		// 	if (sz % 16) != 0 {
		// 		cnt++
		// 	}

		// 	for i := 0; i < cnt; i++ {
		// 		if i+1 < cnt {
		// 			fmt.Printf("% X\n", pkt.Payload[start:start+16])
		// 		} else {
		// 			a := (sz % 16)
		// 			if sz%16 != 0 {
		// 				fmt.Printf("% X\n", pkt.Payload[start:start+a])
		// 			} else {
		// 				fmt.Printf("% X\n", pkt.Payload[start:start+16])
		// 			}
		// 		}
		// 		start += 16
		// 	}
		// }
	}

	elapsed := time.Since(start)
	fmt.Println("elapsedTime:", elapsed, "fames:", frameCount, "fps:", float64(frameCount)/float64(elapsed.Seconds()))
}
