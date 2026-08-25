package support

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestSizeOfCGoStruct(t *testing.T) {
	tests := []struct {
		// Name of Go wrapper struct
		name  string
		input uintptr
		want  uintptr
	}{
		{name: "ApmIntProcInfo", input: unsafe.Sizeof(ApmIntProcInfo{}),
			want: sizeof_ApmIntProcInfo},
		{name: "DotnetProcInfo", input: unsafe.Sizeof(DotnetProcInfo{}),
			want: sizeof_DotnetProcInfo},
		{name: "PHPProcInfo", input: unsafe.Sizeof(PHPProcInfo{}),
			want: sizeof_PHPProcInfo},
		{name: "RubyProcInfo", input: unsafe.Sizeof(RubyProcInfo{}),
			want: sizeof_RubyProcInfo},
		// Discord: Trace crosses the eBPF boundary as one whole record rather
		// than field by field, so a hand-edit of this generated mirror does
		// not fail the build -- it fails at runtime as "trace record too
		// small". Pin it here instead.
		{name: "Trace", input: unsafe.Sizeof(Trace{}), want: Sizeof_Trace},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equalf(t, tt.want, tt.input,
				"unsafe.Sizeof(%v{}) = %v, want %v", tt.name, tt.input, tt.want)
		})
	}
}

// TestTraceFieldOffsets pins the offsets the eBPF side writes at literally.
// Discord: the tracer objects store erlang_pid_key at a fixed byte offset
// (see doc/discord-fork.md section 3.9), so inserting or resizing any field
// above it silently redirects that store into a neighbour rather than
// failing to compile. Sizeof_Trace alone would not catch a same-size
// reordering.
func TestTraceFieldOffsets(t *testing.T) {
	tests := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{name: "Origin", got: unsafe.Offsetof(Trace{}.Origin), want: 708},
		{name: "Offtime", got: unsafe.Offsetof(Trace{}.Offtime), want: 712},
		{name: "Erlang_pid_key",
			got: unsafe.Offsetof(Trace{}.Erlang_pid_key), want: 720},
		{name: "Frame_data", got: unsafe.Offsetof(Trace{}.Frame_data),
			want: 728},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equalf(t, tt.want, tt.got,
				"unsafe.Offsetof(Trace{}.%v) = %v, want %v",
				tt.name, tt.got, tt.want)
		})
	}
}
