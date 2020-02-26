package snow3g

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestSnow3G(t *testing.T) {
	type TestSet struct {
		Key        string
		IV         string
		R1PostInit string
		R2PostInit string
		R3PostInit string
		KeyStream  []string
	}

	testSets := map[string]TestSet{
		"3.3. Test Set 1": TestSet{
			Key: "2B D6 45 9F 82 C5 B3 00 95 2C 49 10 48 81 FF 48",
			IV:  "EA 02 47 14 AD 5C 4D 84 DF 1F 9B 25 1C 0B F4 5F",
			KeyStream: []string{
				"AB EE 97 04",
				"7A C3 13 73",
			},
			R1PostInit: "61DA9249",
			R2PostInit: "427DF38C",
			R3PostInit: "0FB6B101",
		},
		"3.4. Test Set 2": TestSet{
			Key: "8C E3 3E 2C C3 C0 B5 FC 1F 3D E8 A6 DC 66 B1 F3",
			IV:  "D3 C5 D5 92 32 7F B1 1C DE 55 19 88 CE B2 F9 B7",
			KeyStream: []string{
				"EF F8 A3 42",
				"F7 51 48 0F",
			},
			R1PostInit: "65130120",
			R2PostInit: "A14C7DBD",
			R3PostInit: "B68B551A",
		},
		"3.5. Test Set 3": TestSet{
			Key: "40 35 C6 68 0A F8 C6 D1 A8 FF 86 67 B1 71 40 13",
			IV:  "62 A5 40 98 1B A6 F9 B7 45 92 B0 E7 86 90 F7 1B",
			KeyStream: []string{
				"A8 C8 74 A9",
				"7A E7 C4 F8",
			},
			R1PostInit: "6599AA50",
			R2PostInit: "5EA9188B",
			R3PostInit: "F41889FC",
		},
		"3.6. Test Set 4": TestSet{
			Key:       "0D ED 72 63 10 9C F9 2E 33 52 25 5A 14 0E 0F 76",
			IV:        "6B 68 07 9A 41 A7 C4 C9 1B EF D7 9F 7F DC C2 33",
			KeyStream: make([]string, 2500),
		},
	}

	testSets["3.6. Test Set 4"].KeyStream[0] = "D7 12 C0 5C"
	testSets["3.6. Test Set 4"].KeyStream[1] = "A9 37 C2 A6"
	testSets["3.6. Test Set 4"].KeyStream[2] = "EB 7E AA E3"
	testSets["3.6. Test Set 4"].KeyStream[2499] = "9C 0D B3 AA"

	for n, ts := range testSets {
		t.Run(n, func(t *testing.T) {
			keyB, _ := hex.DecodeString(strings.Join(strings.Fields(ts.Key), ""))
			ivB, _ := hex.DecodeString(strings.Join(strings.Fields(ts.IV), ""))
			r1B, _ := hex.DecodeString(ts.R1PostInit)
			r2B, _ := hex.DecodeString(ts.R2PostInit)
			r3B, _ := hex.DecodeString(ts.R3PostInit)

			k := [4]uint32{}
			for i := 0; i < 4; i += 1 {
				k[i] = binary.BigEndian.Uint32(keyB[i*4 : i*4+4])
			}

			iv := [4]uint32{}
			for i := 0; i < 4; i += 1 {
				iv[i] = binary.BigEndian.Uint32(ivB[i*4 : i*4+4])
			}

			s := &Snow3G{}
			s.Initialize(k, iv)

			if len(ts.R1PostInit) > 0 {
				assert.Equal(t, binary.BigEndian.Uint32(r1B), s.FSM.R1, "R1 should be equal.")
			}

			if len(ts.R2PostInit) > 0 {
				assert.Equal(t, binary.BigEndian.Uint32(r2B), s.FSM.R2, "R2 should be equal.")
			}

			if len(ts.R3PostInit) > 0 {
				assert.Equal(t, binary.BigEndian.Uint32(r3B), s.FSM.R3, "R3 should be equal.")
			}

			ks := s.GenerateKeystream(len(ts.KeyStream))

			for i, kss := range ts.KeyStream {
				kss = strings.Join(strings.Fields(kss), "")
				if len(kss) > 0 {
					ksb, _ := hex.DecodeString(kss)
					assert.Equal(t, binary.BigEndian.Uint32(ksb), ks[i], fmt.Sprintf("KeyStream[%d] should be equal.", i))
				}
			}
		})
	}
}
