package uea2

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/gordon2020t/snow3g"
	"github.com/stretchr/testify/assert"
)

func TestUEA2(t *testing.T) {
	type TestSet struct {
		CountC     string
		Bearer     uint32
		Direction  snow3g.Direction
		CK         string
		BitLength  uint32
		Plaintext  string
		Ciphertext string
	}

	testSets := map[string]TestSet{
		"4.3. Test Set 1": TestSet{
			CountC:    "72A4F20F",
			Bearer:    0x0c,
			Direction: snow3g.KEY_DOWNLINK,
			CK:        "2B D6 45 9F 82 C5 B3 00 95 2C 49 10 48 81 FF 48",
			BitLength: 798,
			Plaintext: `7EC61272 743BF161 4726446A 6C38CED1
                        66F6CA76 EB543004 4286346C EF130F92
                        922B0345 0D3A9975 E5BD2EA0 EB55AD8E
                        1B199E3E C4316020 E9A1B285 E7627953
                        59B7BDFD 39BEF4B2 484583D5 AFE082AE
                        E638BF5F D5A60619 3901A08F 4AB41AAB
                        9B134880`,
			Ciphertext: `8CEBA629 43DCED3A 0990B06E A1B0A2C4
                         FB3CEDC7 1B369F42 BA64C1EB 6665E72A
                         A1C9BB0D EAA20FE8 6058B8BA EE2C2E7F
                         0BECCE48 B52932A5 3C9D5F93 1A3A7C53
                         2259AF43 25E2A65E 3084AD5F 6A513B7B
                         DDC1B65F 0AA0D97A 053DB55A 88C4C4F9
                         605E4140`,
		},
		"4.4. Test Set 2": TestSet{
			CountC:    "E28BCF7B",
			Bearer:    0x18,
			Direction: snow3g.KEY_UPLINK,
			CK:        "EF A8 B2 22 9E 72 0C 2A 7C 36 EA 55 E9 60 56 95",
			BitLength: 510,
			Plaintext: `10111231 E060253A 43FD3F57 E37607AB
                        2827B599 B6B1BBDA 37A8ABCC 5A8C550D
                        1BFB2F49 4624FB50 367FA36C E3BC68F1
                        1CF93B15 10376B02 130F812A 9FA169D8`,
			Ciphertext: `E0DA15CA 8E2554F5 E56C9468 DC6C7C12
                         9C568AA5 032317E0 4E072964 6CABEFA6
                         89864C41 0F24F919 E61E3DFD FAD77E56
                         0DB0A9CD 36C34AE4 181490B2 9F5FA2FC`,
		},
		"4.5. Test Set 3": TestSet{
			CountC:     "FA556B26",
			Bearer:     0x03,
			Direction:  snow3g.KEY_DOWNLINK,
			CK:         "5A CB 1D 64 4C 0D 51 20 4E A5 F1 45 10 10 D8 52",
			BitLength:  120,
			Plaintext:  `AD9C441F 890B38C4 57A49D42 1407E8`,
			Ciphertext: `BA0F3130 0334C56B 52A7497C BAC046`,
		},
		"4.6. Test Set 4": TestSet{
			CountC:    "398A59B4",
			Bearer:    0x05,
			Direction: snow3g.KEY_DOWNLINK,
			CK:        "D3 C5 D5 92 32 7F B1 1C 40 35 C6 68 0A F8 C6 D1",
			BitLength: 253,
			Plaintext: `981BA682 4C1BFB1A B4854720 29B71D80
                         8CE33E2C C3C0B5FC 1F3DE8A6 DC66B1F0`,
			Ciphertext: `989B719C DC33CEB7 CF276A52 827CEF94
                         A56C40C0 AB9D81F7 A2A9BAC6 0E11C4B0`,
		},
		"4.7. Test Set 5": TestSet{
			CountC:    "72A4F20F",
			Bearer:    0x09,
			Direction: snow3g.KEY_UPLINK,
			CK:        "60 90 EA E0 4C 83 70 6E EC BF 65 2B E8 E3 65 66",
			BitLength: 837,
			Plaintext: `40981BA6 824C1BFB 4286B299 783DAF44
                        2C099F7A B0F58D5C 8E46B104 F08F01B4
                        1AB48547 2029B71D 36BD1A3D 90DC3A41
                        B46D5167 2AC4C966 3A2BE063 DA4BC8D2
                        808CE33E 2CCCBFC6 34E1B259 060876A0
                        FBB5A437 EBCC8D31 C19E4454 318745E3
                        98764598 7A986F2C B0`,
			Ciphertext: `5892BBA8 8BBBCAAE AE769AA0 6B683D3A
                         17CC04A3 69881697 435E44FE D5FF9AF5
                         7B9E890D 4D5C6470 9885D48A E40690EC
                         043BAAE9 705796E4 A9FF5A4B 8D8B36D7
                         F3FE57CC 6CFD6CD0 05CD3852 A85E94CE
                         6BCD90D0 D07839CE 09733544 CA8E3508
                         43248550 922AC128 18`,
		},
	}

	for n, ts := range testSets {
		t.Run(n, func(t *testing.T) {
			ck, _ := hex.DecodeString(strings.Join(strings.Fields(ts.CK), ""))
			countB, _ := hex.DecodeString(ts.CountC)
			count := binary.BigEndian.Uint32(countB)
			bearer := ts.Bearer
			direction := ts.Direction
			blength := ts.BitLength
			plaintext, _ := hex.DecodeString(strings.Join(strings.Fields(ts.Plaintext), ""))
			expected, _ := hex.DecodeString(strings.Join(strings.Fields(ts.Ciphertext), ""))

			u := NewUEA2(ck, count, bearer, direction)
			ciphertext := u.Encrypt(plaintext, blength)

			assert.Equal(t, expected, ciphertext, "Should be equal")
		})
	}
}
