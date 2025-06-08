//go:build linux && cgo

package netlink

import (
	"unsafe"
)

// SockDiagReq is the Netlink request struct, as in linux/inet_diag.h
// Note that netlink messages use host byte ordering. This struct's
// definition has been pulled from github.com/m-lab/tcp-info. Check
// sock_diag(7) for more information.
type SockDiagReq struct {
	Family   uint8
	Protocol uint8
	Ext      uint8
	Pad      uint8
	States   uint32
	ID       InetDiagSockID
}

// SizeOfSockDiagReq is the size of the struct.
// TODO should we just make this explicit in the code?
const SizeOfSockDiagReq = int(unsafe.Sizeof(SockDiagReq{})) // Should be 0x38

// Len is required to implement the nl.NetlinkRequestData interface
func (req SockDiagReq) Len() int {
	return SizeOfSockDiagReq
}

// Serialize is required to implement the nl.NetlinkRequestData interface
func (req SockDiagReq) Serialize() []byte {
	return (*(*[SizeOfSockDiagReq]byte)(unsafe.Pointer(&req)))[:]
}

// InetDiagSockID is the binary linux representation of a socket, as in linux/inet_diag.h.
// This struct definition has been adapted from github.com/m-lab/tcp-info. This is basically
// the Golang counterpart of 'struct inet_diag_sockid'. Check sock_diag(7) for more information.
type InetDiagSockID struct {
	DiagSPort  DiagPortT
	DiagDPort  DiagPortT
	DiagSrc    DiagIPT
	DiagDst    DiagIPT
	DiagIf     DiagNetIfT
	DiagCookie DiagCookieT
}

// DiagPortT encodes an InetDiagSockID port.
type DiagPortT [2]byte

// DiagIPT encodes an InetDiagSockID IPv{4,6} address.
type DiagIPT [16]byte

// DiagNetIfT encodes an InetDiagSockID Interface field.
type DiagNetIfT [4]byte

// Types for LinuxSockID fields.
type DiagCookieT [8]byte
