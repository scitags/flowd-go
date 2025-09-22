package progs

import "embed"

//go:embed marker/*.o
//go:embed skops/*.o
var ebpfPrograms embed.FS

// GetMarkerProgram will return an embedded eBPF program carrying
// out IPv6 header marking based on the provided path. This path
// is assumed to be provided in the context of the marker/
// subdirectory so as to decouple the progs' package structure
// from the outside.
func GetMarkerProgram(path string) ([]byte, error) {
	return ebpfPrograms.ReadFile("marker/" + path)
}

// GetSkopsProgram will return an embedded eBPF program carrying
// out TCP data acquisition based on the provided path. This path
// is assumed to be provided in the context of the skops/
// subdirectory so as to decouple the progs' package structure
// from the outside.
func GetSkopsProgram(path string) ([]byte, error) {
	return ebpfPrograms.ReadFile("skops/" + path)
}
