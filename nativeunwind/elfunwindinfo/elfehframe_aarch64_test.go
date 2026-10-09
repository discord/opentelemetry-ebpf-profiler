// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package elfunwindinfo

import (
	"testing"

	"go.opentelemetry.io/ebpf-profiler/support"
)

func TestARMX20UnwindRule(t *testing.T) {
	regs := newVMRegsARM()
	regs.cfa = vmReg{reg: armRegSP, off: 64}
	regs.ra = vmReg{reg: regCFA, off: -40}

	info := regs.getUnwindInfoARM()
	if info.Flags&(support.UnwindFlagX20CFA|support.UnwindFlagX20Invalid) != 0 {
		t.Fatalf("unchanged x20 has flags %#x", info.Flags)
	}

	regs.x20 = vmReg{reg: regCFA, off: -32}
	info = regs.getUnwindInfoARM()
	if info.Flags&support.UnwindFlagX20CFA == 0 || info.X20Param != -32 {
		t.Fatalf("saved x20 rule: %+v", info)
	}

	regs.x20 = vmReg{reg: regUndefined}
	info = regs.getUnwindInfoARM()
	if info.Flags&support.UnwindFlagX20Invalid == 0 || info.Flags&support.UnwindFlagX20CFA != 0 {
		t.Fatalf("undefined x20 rule: %+v", info)
	}

	regs.x20 = vmReg{reg: regCFA, off: 1 << 32}
	info = regs.getUnwindInfoARM()
	if info.Flags&support.UnwindFlagX20Invalid == 0 {
		t.Fatalf("out-of-range x20 offset: %+v", info)
	}
}

func TestARMX21UnwindRule(t *testing.T) {
	regs := newVMRegsARM()
	regs.cfa = vmReg{reg: armRegSP, off: 64}
	regs.ra = vmReg{reg: regCFA, off: -40}

	if info := regs.getUnwindInfoARM(); info.X21Rule != support.UnwindX21Same {
		t.Fatalf("unchanged x21 rule: %+v", info)
	}
	regs.x21 = vmReg{reg: regCFA, off: -24}
	if info := regs.getUnwindInfoARM(); info.X21Rule != support.UnwindX21CFA || info.X21Param != -24 {
		t.Fatalf("saved x21 rule: %+v", info)
	}
	regs.x21 = vmReg{reg: regUndefined}
	if info := regs.getUnwindInfoARM(); info.X21Rule != support.UnwindX21Invalid {
		t.Fatalf("undefined x21 rule: %+v", info)
	}
}
