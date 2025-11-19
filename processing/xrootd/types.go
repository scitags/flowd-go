package xrootd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
)

// Don't leverage unsafe.SizeOf! It won't take padding and co. into
// account...

// Contents mostly plundered from [0]
// 0: https://github.com/PelicanPlatform/pelican/blob/main/metrics/xrootd_metrics.go

type MonHeader struct {
	Code byte   // = | d | f | g | i | p | r | t | u | x
	Pseq byte   // packet sequence
	Plen uint16 // packet length
	Stod uint32 // Unix time at Server start
}

func (m *MonHeader) UnmarshalBinary(data []byte) error {
	m.Code = data[0]
	m.Pseq = data[1]
	m.Plen = binary.BigEndian.Uint16(data[2:4])
	m.Stod = binary.BigEndian.Uint32(data[4:8])

	return nil
}

func (m MonHeader) String() string {
	return fmt.Sprintf("Hdr: {code: %s, pseq: %d, plen: %d, stod: %d}", string(m.Code), m.Pseq, m.Plen, m.Stod)
}

type RecType byte

// See [0].
// 0: https://github.com/xrootd/xrootd/blob/f3b2e86b9b80bb35f97dd4ad30c4cd5904902a4c/src/XrdXrootd/XrdXrootdMonData.hh#L173
const (
	IsClose RecType = iota
	IsOpen
	IsTime
	IsXfr
	IsDisc
)

// TODO: leverage stringer!
var recTypeMap = map[RecType]string{
	IsClose: "isClose",
	IsOpen:  "isOpen",
	IsTime:  "isTime",
	IsXfr:   "isXfr",
	IsDisc:  "isDisc",
}

func (r RecType) String() string {
	s, ok := recTypeMap[r]
	if !ok {
		return "unknown"
	}
	return s
}

type MonFileHdr struct {
	RecType RecType
	RecFlag byte
	RecSize uint16

	// This field holds the union data that's to be interpreted based on the
	// value of RecType:
	//   !IsTime: fileID
	//    IsDisc: userID
	//    IsTime: isXFR recs << 32 | total recs
	IdRecs uint32
}

func (m *MonFileHdr) UnmarshalBinary(data []byte) error {
	if data[0] > byte(IsDisc) {
		return fmt.Errorf("unknown RecType %v", data[0])
	}

	m.RecType = RecType(data[0])
	m.RecFlag = data[1]
	m.RecSize = binary.BigEndian.Uint16(data[2:4])
	m.IdRecs = binary.BigEndian.Uint32(data[4:8])

	return nil
}

func (m MonFileHdr) String() string {
	return fmt.Sprintf("MonFileHdr: {type: %s, flag: %x, size: %d, Id: %d}", m.RecType, m.RecFlag, m.RecSize, m.IdRecs)
}

type MonFileTOD struct {
	Hdr  MonFileHdr
	TBeg uint32
	TEnd uint32
	SID  uint64
}

func (m *MonFileTOD) UnmarshalBinary(data []byte) error {
	m.TBeg = binary.BigEndian.Uint32(data[8:12])
	m.TEnd = binary.BigEndian.Uint32(data[12:16])
	m.SID = binary.BigEndian.Uint64(data[16:24])

	return nil
}

func (m MonFileTOD) String() string {
	return fmt.Sprintf("MonFileTOD: {\n\t\t%s,\n\t\ttBeg: %d, tEnd: %d, sID: %d\n\t}", m.Hdr, m.TBeg, m.TEnd, m.SID)
}

type MonStatXFR struct {
	Read  uint64 // Bytes read from file using read()
	Readv uint64 // Bytes read from file using readv()
	Write uint64 // Bytes written to file
}

func (m *MonStatXFR) UnmarshalBinary(data []byte) error {
	m.Read = binary.BigEndian.Uint64(data[0:8])
	m.Readv = binary.BigEndian.Uint64(data[8:16])
	m.Write = binary.BigEndian.Uint64(data[16:24])

	return nil
}

func (m MonStatXFR) String() string {
	return fmt.Sprintf("MonStatXFR: {\n\t\t\tRead: %d,\n\t\t\tReadv: %d,\n\t\t\tWrite: %d\n\t\t}", m.Read, m.Readv, m.Write)
}

// File close event
type MonFileCLS struct {
	Hdr MonFileHdr
	Xfr MonStatXFR
	// Ops *MonStatOPS
	// Ssq *MonStatSSQ
}

func (m *MonFileCLS) UnmarshalBinary(data []byte) error {
	if len(data) < 24 {
		return fmt.Errorf("CLS record too small!")
	}
	m.Xfr.UnmarshalBinary(data)
	return nil
}

func (m MonFileCLS) String() string {
	return fmt.Sprintf("MonFileCLS: {\n\t\t%s,\n\t\t%s\n\t}", m.Hdr, m.Xfr)
}

// File disconnect event
type MonFileDSC struct {
	Hdr MonFileHdr
}

func (m MonFileDSC) String() string {
	return fmt.Sprintf("MonFileDSC: {\n\t\t%s\n\t}", m.Hdr)
}

type MonFileOPN struct {
	Hdr      MonFileHdr
	FileSize uint64
	Ufn      *MonFileLFN
}

func (m *MonFileOPN) UnmarshalBinary(data []byte) error {
	m.FileSize = binary.BigEndian.Uint64(data[0:8])

	// If there's a LFN included...
	if m.Hdr.RecFlag&0x01 != 0 {
		tmp := MonFileLFN{}

		if err := tmp.UnmarshalBinary(data[8:]); err != nil {
			return fmt.Errorf("error unmarshaling LFN: %w", err)
		}

		m.Ufn = &tmp
	}

	return nil
}

func (m MonFileOPN) String() string {
	if m.Ufn != nil {
		return fmt.Sprintf("MonFileOPN: {\n\t\t%s\n\t\tFileSize: %d\n\t\tUfn: %s\n\t}", m.Hdr, m.FileSize, m.Ufn)
	}
	return fmt.Sprintf("MonFileOPN: {\n\t\t%s\n\t\tFileSize: %d\n\t}", m.Hdr, m.FileSize)
}

type MonFileLFN struct {
	userId uint32
	Lfn    string
}

func (m *MonFileLFN) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("LFN too small (%d)", len(data))
	}

	m.userId = binary.BigEndian.Uint32(data[0:4])
	m.Lfn = string(data[4:])

	return nil
}

func (m MonFileLFN) String() string {
	return fmt.Sprintf("{userId: %d, lfn: %s}", m.userId, m.Lfn)
}

type MonFileXFR struct {
	Hdr MonFileHdr
	Xfr MonStatXFR
}

type MonFStream struct {
	Tod MonFileTOD
	Cls *MonFileCLS
	Dsc *MonFileDSC
	Opn *MonFileOPN
	Xfr *MonFileXFR
}

func (m *MonFStream) UnmarshalBinary(data []byte) error {
	buff := bytes.NewBuffer(data)

	slog.Debug("decoding MonFStream", "len", buff.Len())

	tmpHdr := MonFileHdr{}

	if err := tmpHdr.UnmarshalBinary(buff.Next(8)); err != nil {
		return fmt.Errorf("error unmarshaling initial MonFileHdr: %w", err)
	}

	if err := m.Tod.UnmarshalBinary(buff.Next(16)); err != nil {
		return fmt.Errorf("error unmarshaling TOD: %w", err)
	}
	m.Tod.Hdr = tmpHdr

	slog.Debug("decoding MonFStream", "len", buff.Len())

	for buff.Len() > 0 {
		if err := tmpHdr.UnmarshalBinary(buff.Next(8)); err != nil {
			return fmt.Errorf("error unmarshaling: %w", err)
		}

		slog.Debug("decoding MonFStream", "len", buff.Len())

		switch tmpHdr.RecType {
		case IsOpen:
			slog.Debug("decoding IsOpen", "size", tmpHdr.RecSize)
			tmp := MonFileOPN{Hdr: tmpHdr}

			// Read the rest of the struct (don't take into account the already read header)
			if err := tmp.UnmarshalBinary(buff.Next(int(tmpHdr.RecSize) - 8)); err != nil {
				return fmt.Errorf("error unmarshaling: %w", err)
			}
			m.Opn = &tmp
		case IsClose:
			slog.Debug("decoding IsClose", "size", tmpHdr.RecSize)
			tmp := MonFileCLS{Hdr: tmpHdr}

			if err := tmp.UnmarshalBinary(buff.Next(int(tmpHdr.RecSize) - 8)); err != nil {
				return fmt.Errorf("error unmarshaling: %w", err)
			}
			m.Cls = &tmp
		case IsDisc:
			slog.Debug("decoding IsDisc", "size", tmpHdr.RecSize)
			m.Dsc = &MonFileDSC{Hdr: tmpHdr}
		default:
			buff.Next(int(tmpHdr.RecSize) - 8)
			slog.Debug("ignoring", "type", tmpHdr.RecType, "size", tmpHdr.RecSize)
		}
	}

	return nil
}

func (m MonFStream) String() string {
	s := fmt.Sprintf("MonFStream: {\n\t%s,", m.Tod)

	if m.Opn != nil {
		s = fmt.Sprintf("%s\n\t%s,", s, m.Opn)
	}

	if m.Cls != nil {
		s = fmt.Sprintf("%s\n\t%s,", s, m.Cls)
	}

	if m.Dsc != nil {
		s = fmt.Sprintf("%s\n\t%s", s, m.Dsc)
	}

	return s + "\n}"
}
