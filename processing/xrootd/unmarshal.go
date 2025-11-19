package xrootd

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type MonMessage struct {
	Hdr MonHeader

	// For Hdr.Code:
	//   =, p, and x record-types, this is always 0
	//   i, T, u, and U , this is a connection ID
	//   d, this is a file ID.
	// For other codes, this value has no meaning and
	// it **is not** encoded in UDP datagrams.
	DictId uint32

	Info    string
	Fstream *MonFStream
}

func (m MonMessage) String() string {
	s := fmt.Sprintf("%s", m.Hdr)

	switch m.Hdr.Code {
	case '=', 'u', 'd':
		s = fmt.Sprintf("%s\nDictId: %d,\nInfo: %s", s, m.DictId, m.Info)
	case 'f':
		s = fmt.Sprintf("%s\n%s", s, m.Fstream)
	}

	return s
}

// We should do some bounds checking to avoid panics...
func ParseDatagram(data []byte) (*MonMessage, error) {
	buff := bytes.NewBuffer(data)

	if buff.Available() < 8 {
		return nil, fmt.Errorf("low header size %d, expected at least 8 bytes", len(data))
	}

	hdr := MonHeader{}
	hdr.UnmarshalBinary(buff.Next(8))

	// Get the dict id to correlate information.
	// Only do it for records where it actually shows up!
	dictId := binary.BigEndian.Uint32(data[8:12])

	switch hdr.Code {
	case '=', 'u', 'd':
		// Consume the dictId
		buff.Next(4)
		return &MonMessage{
			Hdr:    hdr,
			DictId: dictId,
			Info:   string(buff.Next(int(hdr.Plen) - 12)),
		}, nil
	case 'f':
		if buff.Len() < 24 {
			return nil, fmt.Errorf("less that 24 bytes available, not a valid f-stream packet")
		}
		fStream := MonFStream{}
		if err := fStream.UnmarshalBinary(buff.Next(int(hdr.Plen) - 8)); err != nil {
			return nil, fmt.Errorf("error unmarshaling fStream: %w", err)
		}

		// fmt.Printf("first header size: %d\n", binary.BigEndian.Uint16(data[10:12]))

		return &MonMessage{
			Hdr:     hdr,
			DictId:  dictId,
			Fstream: &fStream,
		}, nil
	}

	return nil, fmt.Errorf("code %q not implemented", hdr.Code)
}
