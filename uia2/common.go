// Code adapted from ETSI / SAGE specification of the 3GPP Confidentiality and Integrity Algorithms UEA2 & UIA2.
// Document 1: UEA2 and UIA2 Specification. Version 2.1 from the 16th March 2009, annex 4.
// https://www.gsma.com/security/wp-content/uploads/2019/05/uea2uia2d1v21.pdf

package uia2

func mul64x(v, c uint64) uint64 {
	if v&uint64(0x8000000000000000) > 0 {
		return (v << 1) ^ c
	}

	return v << 1
}

func mul64xpow(v uint64, i uint8, c uint64) uint64 {
	for i > 0 {
		v = mul64x(v, c)
		i = i - 1
	}
	return v
}

func mul64(v, p, c uint64) uint64 {
	r := uint64(0)

	for i := 0; i < 64; i += 1 {
		if ((p >> i) & 0x1) > 0 {
			r ^= mul64xpow(v, uint8(i), c)
		}
	}

	return r
}

func mask8bit(n int) uint8 {
	return uint8(0xff ^ ((1 << (8 - n)) - 1))
}
