package types

import (
	"encoding/json"
	"testing"
)

func TestEnrichmentVerbosityControl(t *testing.T) {
	e := &Enrichment{
		TCPInfo: &TCPInfo{
			Pmtu:  1500,
			State: 5,
		},
	}

	ogEnc, err := json.Marshal(e)
	if err != nil {
		t.Errorf("error marshalling: %v", err)
	}

	e.Verbosity = "lean"
	leanEnc, err := json.Marshal(e)
	if err != nil {
		t.Errorf("error marshalling: %v", err)
	}

	e.Verbosity = "wrong"
	wrongEnc, err := json.Marshal(e)
	if err != nil {
		t.Errorf("error marshalling: %v", err)
	}

	if len(ogEnc) != len(wrongEnc) || len(leanEnc) > len(ogEnc) {
		t.Errorf("unexpected encoded sizes: original: %d, lean: %d, wrong: %d", len(ogEnc), len(leanEnc), len(wrongEnc))
	}

	// fmt.Printf("original: %s\n\nlean: %s\n\nwrong: %s\n", ogEnc, leanEnc, wrongEnc)
}
