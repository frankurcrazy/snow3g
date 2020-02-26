// Code adapted from ETSI / SAGE specification of the 3GPP Confidentiality and Integrity Algorithms UEA2 & UIA2.
// Document 2: SNOW 3G Specification. Version 1.1 from the 6th September 2006, annex 4.
// https://www.gsma.com/security/wp-content/uploads/2019/05/snow3gspec.pdf

package snow3g

func mulx(v, c uint8) uint8 {
	if v&uint8(0x80) > 0 {
		return (v << 1) ^ c
	}

	return (v << 1)
}

func mulxpow(v uint8, i uint8, c uint8) uint8 {
	if i == 0 {
		return v
	}

	return mulx(mulxpow(v, i-1, c), c)
}

func mulalpha(c uint8) uint32 {
	return ((uint32(mulxpow(c, 23, 0xa9)) << 24) |
		(uint32(mulxpow(c, 245, 0xa9)) << 16) |
		(uint32(mulxpow(c, 48, 0xa9)) << 8) |
		(uint32(mulxpow(c, 239, 0xa9))))
}

func divalpha(c uint8) uint32 {
	return ((uint32(mulxpow(c, 16, 0xa9)) << 24) |
		(uint32(mulxpow(c, 39, 0xa9)) << 16) |
		(uint32(mulxpow(c, 6, 0xa9)) << 8) |
		(uint32(mulxpow(c, 64, 0xa9))))
}

func mul64x(v, c uint64) uint64 {
	if v&uint64(0x8000000000000000) > 0 {
		return (v << 1) ^ c
	}

	return v << 1
}

func mul64xpow(v uint64, i uint8, c uint64) uint64 {
	if i == 0 {
		return v
	}

	return mul64x(mul64xpow(v, i-1, c), c)
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
