//go:build linux

package netlink

import (
	ne "github.com/josharian/native"
)

func Htons(in uint16) uint16 {
	if !ne.IsBigEndian {
		return uint16((in&0xFF)<<8) | uint16((in>>8)&0xFF)
	}
	return in
}
