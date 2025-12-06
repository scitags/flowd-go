package types

import "encoding/binary"

func (f FlowID) MarshalBinary() ([]byte, error) {
	enc := append([]byte{}, f.Src.Addr().AsSlice()...)
	enc = append(enc, f.Dst.Addr().AsSlice()...)
	binary.LittleEndian.AppendUint16(enc, f.Src.Port())
	binary.LittleEndian.AppendUint16(enc, f.Dst.Port())
	return enc, nil
}
