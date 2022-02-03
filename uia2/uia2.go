// Code adapted from ETSI / SAGE specification of the 3GPP Confidentiality and Integrity Algorithms UEA2 & UIA2.
// Document 1: UEA2 and UIA2 Specification. Version 2.1 from the 16th March 2009, annex 4.
// https://www.gsma.com/security/wp-content/uploads/2019/05/uea2uia2d1v21.pdf

package uia2

import (
	"bytes"
	"github.com/pedroalbanese/snow3g"
)

type UIA2 struct {
	snow3g *snow3g.Snow3G
	ks     []uint32
	p      uint64
	q      uint64
}

func NewUIA2(ik []byte, count uint32, fresh uint32, direction snow3g.Direction) *UIA2 {
	s3g := &snow3g.Snow3G{}

	k := [4]uint32{}
	for i := 0; i < 4; i += 1 {
		k[3-i] = (uint32(ik[4*i]) << 24) ^ (uint32(ik[4*i+1]) << 16) ^
			(uint32(ik[4*i+2]) << 8) ^ (uint32(ik[4*i+3]))
	}

	iv := [4]uint32{}
	iv[3] = count
	iv[2] = fresh
	iv[1] = count ^ (uint32(direction) << 31)
	iv[0] = fresh ^ (uint32(direction) << 15)

	s3g.Initialize(k, iv)
	ks := s3g.GenerateKeystream(5)
	p := (uint64(ks[0]) << 32) | (uint64(ks[1]))
	q := (uint64(ks[2]) << 32) | (uint64(ks[3]))

	return &UIA2{
		snow3g: s3g,
		ks:     ks,
		p:      p,
		q:      q,
	}
}

func (u *UIA2) F9(data []byte, blength uint64) []byte {
	zeroBits := blength & 63
	var d int64

	if zeroBits == 0 {
		d = int64(blength >> 6) + 1
	} else {
		d = int64(blength >> 6) + 2
	}

	eval := uint64(0x00)
	c := uint64(0x1b)

	for i := int64(0); i <= d-3; i += 1 {
		v := eval ^ ((uint64(data[8*i]) << 56) | (uint64(data[8*i+1]) << 48) |
			(uint64(data[8*i+2]) << 40) | (uint64(data[8*i+3]) << 32) |
			(uint64(data[8*i+4]) << 24) | (uint64(data[8*i+5]) << 16) |
			(uint64(data[8*i+6]) << 8) | (uint64(data[8*i+7])))
		eval = mul64(v, u.p, c)
	}

	if zeroBits == 0 {
		zeroBits = 64
	}

	md2 := uint64(0)
	i := int64(0)
	for ; zeroBits > 7; i, zeroBits = i+1, zeroBits-8 {
		md2 |= (uint64(data[8*(d-2)+i]) << (8 * (7 - i)))
	}

	if zeroBits > 0 {
		md2 |= (uint64(data[8*(d-2)+i]&mask8bit(int(zeroBits))) << (8 * (7 - i)))
	}

	v := eval ^ md2
	eval = mul64(v, u.p, c)
	eval ^= blength
	eval = mul64(eval, u.q, c)

	macI := make([]byte, 4)
	for i := 0; i < 4; i += 1 {
		macI[i] = uint8(((eval >> (56 - (i * 8))) ^ (uint64(u.ks[4]) >> (24 - (i * 8)))) & 0xff)
	}

	return macI
}

/* Alias for F9 */
func (u *UIA2) Hash(data []byte, blength uint64) []byte {
	return u.F9(data, blength)
}

func (e *UIA2) Verify(m []byte, blen uint64, mac []byte) bool {
	chksum := e.Hash(m, blen)

	return bytes.Compare(chksum, mac) == 0
}
