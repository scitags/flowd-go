package types

import "encoding/binary"

func (f FlowID) MarshalBinary() ([]byte, error) {
	enc := append([]byte{}, f.Src.IP...)
	enc = append(enc, f.Dst.IP...)
	binary.LittleEndian.AppendUint16(enc, f.Src.Port)
	binary.LittleEndian.AppendUint16(enc, f.Dst.Port)
	return enc, nil
}
