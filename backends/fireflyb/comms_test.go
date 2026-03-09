package fireflyb

import (
	"net/netip"
	"testing"
	"time"

	glowdTypes "github.com/scitags/flowd-go/types"
)

func TestValidateCollectorFlow(t *testing.T) {
	now := time.Now().UTC()

	validStart := glowdTypes.FlowID{
		State:    glowdTypes.START,
		Family:   glowdTypes.IPv6,
		Protocol: glowdTypes.TCP,
		Src:      netip.MustParseAddrPort("2001:db8::1:1234"),
		Dst:      netip.MustParseAddrPort("2001:db8::2:5678"),
		StartTs:  now,
	}

	tests := []struct {
		name    string
		flowID  glowdTypes.FlowID
		wantErr bool
	}{
		{name: "valid start", flowID: validStart, wantErr: false},
		{
			name: "unspecified source",
			flowID: glowdTypes.FlowID{
				State:    glowdTypes.START,
				Family:   glowdTypes.IPv6,
				Protocol: glowdTypes.TCP,
				Src:      netip.MustParseAddrPort("[::]:1234"),
				Dst:      netip.MustParseAddrPort("2001:db8::2:5678"),
				StartTs:  now,
			},
			wantErr: true,
		},
		{
			name: "zero destination port",
			flowID: glowdTypes.FlowID{
				State:    glowdTypes.START,
				Family:   glowdTypes.IPv6,
				Protocol: glowdTypes.TCP,
				Src:      netip.MustParseAddrPort("2001:db8::1:1234"),
				Dst:      netip.MustParseAddrPort("[2001:db8::2]:0"),
				StartTs:  now,
			},
			wantErr: true,
		},
		{
			name: "start without timestamp",
			flowID: glowdTypes.FlowID{
				State:    glowdTypes.START,
				Family:   glowdTypes.IPv6,
				Protocol: glowdTypes.TCP,
				Src:      netip.MustParseAddrPort("2001:db8::1:1234"),
				Dst:      netip.MustParseAddrPort("2001:db8::2:5678"),
			},
			wantErr: true,
		},
		{
			name: "end without timestamp",
			flowID: glowdTypes.FlowID{
				State:    glowdTypes.END,
				Family:   glowdTypes.IPv6,
				Protocol: glowdTypes.TCP,
				Src:      netip.MustParseAddrPort("2001:db8::1:1234"),
				Dst:      netip.MustParseAddrPort("2001:db8::2:5678"),
				StartTs:  now,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCollectorFlow(tt.flowID)
			if tt.wantErr && err == nil {
				t.Fatalf("expected validation error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}
