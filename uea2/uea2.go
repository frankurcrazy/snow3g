// code adapted from ETSI / SAGE specification of the 3GPP Confidentiality and Integrity Algorithms UEA2 & UIA2.
// Document 1: UEA2 and UIA2 Specification. Version 2.1 from the 16th March 2009, annex 4.
// https://www.gsma.com/security/wp-content/uploads/2019/05/uea2uia2d1v21.pdf

package uea2

import (
	"github.com/frankurcrazy/snow3g"
)

type UEA2 struct {
	snow3g *snow3g.Snow3G
}

/* Create new UEA2 crypter */
func NewUEA2(ck []uint8, count uint32, bearer uint32, direction snow3g.Direction) *UEA2 {
	s3g := &snow3g.Snow3G{}

	e := &UEA2{
		snow3g: s3g,
	}

	k := [4]uint32{}
	for i := 0; i < 4; i += 1 {
		k[3-i] = (uint32(ck[4*i]) << 24) ^ (uint32(ck[4*i+1]) << 16) ^
			(uint32(ck[4*i+2]) << 8) ^ (uint32(ck[4*i+3]))
	}

	iv := [4]uint32{}
	iv[3] = count
	iv[2] = (bearer << 27) | ((uint32(direction) & 0x1) << 26)
	iv[1] = iv[3]
	iv[0] = iv[2]

	s3g.Initialize(k, iv)

	return e
}

/* Alias of F8 */
func (u *UEA2) Encrypt(data []byte, blength uint32) []byte {
	return u.F8(data, blength)
}

/* Alias of F8 */
func (u *UEA2) Decrypt(data []byte, blength uint32) []byte {
	return u.F8(data, blength)
}

func (u *UEA2) F8(data []byte, blength uint32) []byte {
	zeroBits := blength & 0x7
	length := blength >> 3
	if zeroBits > 0 {
		length += 1
	}
	n := int((blength + 31) >> 5)

	ks := u.snow3g.GenerateKeystream(int(n))
	output := make([]byte, length)

	for i := 0; i < n; i += 1 {
		for j := 0; j < 4 && i*4+j < int(length); j += 1 {
			output[4*i+j] = data[4*i+j] ^ uint8((ks[i]>>(8*(3-j)))&0xff)
		}
	}

	/* Discard unaligned trailing bits */
	if zeroBits > 0 {
		output[length-1] = output[length-1] & (uint8(0xff) << (8 - zeroBits))
	}

	/* Discard trailing bytes */
	for j := int(length); j < len(output); j += 1 {
		output[j] = 0
	}

	return output
}
