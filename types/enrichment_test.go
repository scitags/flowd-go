package types

import (
	"encoding/json"
	"testing"
)

func TestEnrichmentMode(t *testing.T) {
	e := &FlowInfo{
		TCPInfo: &TCPInfo{
			Pmtu:  1500,
			State: 5,
		},
	}

	ogEnc, err := json.Marshal(e)
	if err != nil {
		t.Errorf("error marshalling: %v", err)
	}

	e.Mode = "lean"
	leanEnc, err := json.Marshal(e)
	if err != nil {
		t.Errorf("error marshalling: %v", err)
	}

	e.Mode = "wrong"
	wrongEnc, err := json.Marshal(e)
	if err != nil {
		t.Errorf("error marshalling: %v", err)
	}

	if len(ogEnc) != len(wrongEnc) || len(leanEnc) > len(ogEnc) {
		t.Errorf("unexpected encoded sizes: original: %d, lean: %d, wrong: %d", len(ogEnc), len(leanEnc), len(wrongEnc))
	}

	// fmt.Printf("original: %s\n\nlean: %s\n\nwrong: %s\n", ogEnc, leanEnc, wrongEnc)
}

func TestEnrichmentCompatibility(t *testing.T) {
	e := &FlowInfo{
		Mode: "compatible",
		TCPInfo: &TCPInfo{
			Pmtu:  1500,
			State: 5,
		},
	}
	_, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("error marshaling the enrichment: %v", err)
	}
}
