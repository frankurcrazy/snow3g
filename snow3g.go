// Code adapted from ETSI / SAGE specification of the 3GPP Confidentiality and Integrity Algorithms UEA2 & UIA2.
// Document 2: SNOW 3G Specification. Version 1.1 from the 6th September 2006, annex 4.
// https://www.gsma.com/security/wp-content/uploads/2019/05/snow3gspec.pdf

package snow3g

type LFSR struct {
	S0  uint32
	S1  uint32
	S2  uint32
	S3  uint32
	S4  uint32
	S5  uint32
	S6  uint32
	S7  uint32
	S8  uint32
	S9  uint32
	S10 uint32
	S11 uint32
	S12 uint32
	S13 uint32
	S14 uint32
	S15 uint32
}

type FSM struct {
	R1 uint32
	R2 uint32
	R3 uint32
}

type Snow3G struct {
	LFSR LFSR
	FSM  FSM
}

func (s *Snow3G) clockLFSRInitializationMode(f uint32) {
	v := uint32(((s.LFSR.S0 << 8) & 0xffffff00) ^
		(mulalpha(uint8((s.LFSR.S0 >> 24) & 0xff))) ^
		(s.LFSR.S2) ^
		((s.LFSR.S11 >> 8) & 0x00ffffff) ^
		(divalpha(uint8((s.LFSR.S11) & 0xff))) ^
		(f))

	s.LFSR.S0 = s.LFSR.S1
	s.LFSR.S1 = s.LFSR.S2
	s.LFSR.S2 = s.LFSR.S3
	s.LFSR.S3 = s.LFSR.S4
	s.LFSR.S4 = s.LFSR.S5
	s.LFSR.S5 = s.LFSR.S6
	s.LFSR.S6 = s.LFSR.S7
	s.LFSR.S7 = s.LFSR.S8
	s.LFSR.S8 = s.LFSR.S9
	s.LFSR.S9 = s.LFSR.S10
	s.LFSR.S10 = s.LFSR.S11
	s.LFSR.S11 = s.LFSR.S12
	s.LFSR.S12 = s.LFSR.S13
	s.LFSR.S13 = s.LFSR.S14
	s.LFSR.S14 = s.LFSR.S15
	s.LFSR.S15 = v
}

func (s *Snow3G) clockLFSRKeyStreamMode() {
	v := uint32(((s.LFSR.S0 << 8) & 0xffffff00) ^
		(mulalpha(uint8((s.LFSR.S0 >> 24) & 0xff))) ^
		(s.LFSR.S2) ^
		((s.LFSR.S11 >> 8) & 0x00ffffff) ^
		(divalpha(uint8((s.LFSR.S11) & 0xff))))

	s.LFSR.S0 = s.LFSR.S1
	s.LFSR.S1 = s.LFSR.S2
	s.LFSR.S2 = s.LFSR.S3
	s.LFSR.S3 = s.LFSR.S4
	s.LFSR.S4 = s.LFSR.S5
	s.LFSR.S5 = s.LFSR.S6
	s.LFSR.S6 = s.LFSR.S7
	s.LFSR.S7 = s.LFSR.S8
	s.LFSR.S8 = s.LFSR.S9
	s.LFSR.S9 = s.LFSR.S10
	s.LFSR.S10 = s.LFSR.S11
	s.LFSR.S11 = s.LFSR.S12
	s.LFSR.S12 = s.LFSR.S13
	s.LFSR.S13 = s.LFSR.S14
	s.LFSR.S14 = s.LFSR.S15
	s.LFSR.S15 = v
}

func (s *Snow3G) clockFSM() uint32 {
	f := uint32((s.LFSR.S15+s.FSM.R1)&0xffffffff) ^ s.FSM.R2
	r := uint32(s.FSM.R2+(s.FSM.R3^s.LFSR.S5)) & 0xffffffff
	s.FSM.R3 = s2(s.FSM.R2)
	s.FSM.R2 = s1(s.FSM.R1)
	s.FSM.R1 = r

	return f
}

func (s *Snow3G) Initialize(k [4]uint32, iv [4]uint32) {
	var f uint32

	s.LFSR.S15 = k[3] ^ iv[0]
	s.LFSR.S14 = k[2]
	s.LFSR.S13 = k[1]
	s.LFSR.S12 = k[0] ^ iv[1]
	s.LFSR.S11 = k[3] ^ 0xffffffff
	s.LFSR.S10 = k[2] ^ 0xffffffff ^ iv[2]
	s.LFSR.S9 = k[1] ^ 0xffffffff ^ iv[3]
	s.LFSR.S8 = k[0] ^ 0xffffffff
	s.LFSR.S7 = k[3]
	s.LFSR.S6 = k[2]
	s.LFSR.S5 = k[1]
	s.LFSR.S4 = k[0]
	s.LFSR.S3 = k[3] ^ 0xffffffff
	s.LFSR.S2 = k[2] ^ 0xffffffff
	s.LFSR.S1 = k[1] ^ 0xffffffff
	s.LFSR.S0 = k[0] ^ 0xffffffff
	s.FSM.R1 = 0x0
	s.FSM.R2 = 0x0
	s.FSM.R3 = 0x0

	for i := 0; i < 32; i += 1 {
		f = s.clockFSM()
		s.clockLFSRInitializationMode(f)
	}
}

func (s *Snow3G) GenerateKeystream(n int) []uint32 {
	var f uint32

	s.clockFSM()
	s.clockLFSRKeyStreamMode()

	ks := make([]uint32, n)
	for t := 0; t < n; t += 1 {
		f = s.clockFSM()
		ks[t] = f ^ s.LFSR.S0

		s.clockLFSRKeyStreamMode()
	}

	return ks
}
