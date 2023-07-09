package rtsplayer

import (
	"fmt"
	"testing"
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
