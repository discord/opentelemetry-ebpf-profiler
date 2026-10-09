// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/ebpf-profiler/processmanager/ebpf"

import (
	"debug/elf"
	"fmt"
	"strings"

	"github.com/cilium/ebpf/link"
)

// Match beam_jit_call_bif by its mangled name prefix; require one definition.
func beamBIFSymbol(path string) (string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	symbols, symbolsErr := f.Symbols()
	dynamic, dynamicErr := f.DynamicSymbols()
	if symbolsErr != nil && dynamicErr != nil {
		return "", fmt.Errorf("read BEAM ELF symbols: %v; %v", symbolsErr, dynamicErr)
	}
	var name string
	for _, table := range [][]elf.Symbol{symbols, dynamic} {
		for _, symbol := range table {
			if !strings.HasPrefix(symbol.Name, "_Z17beam_jit_call_bif") ||
				elf.ST_TYPE(symbol.Info) != elf.STT_FUNC || symbol.Size == 0 {
				continue
			}
			if name != "" && name != symbol.Name {
				return "", fmt.Errorf("ambiguous BEAM BIF symbol in %s", path)
			}
			name = symbol.Name
		}
	}
	if name == "" {
		return "", fmt.Errorf("BEAM BIF symbol not found in %s", path)
	}
	return name, nil
}

type beamBIFProbeLinks struct {
	entry link.Link
}

type beamDirtyProbeLinks struct {
	entry link.Link
}

func (p *beamDirtyProbeLinks) close() {
	_ = p.entry.Close()
}

func (p *beamBIFProbeLinks) close() {
	_ = p.entry.Close()
}

func (e *ebpfMapsImpl) AttachBEAMBIF(fileID uint64, path string) error {
	e.beamProbeLock.Lock()
	defer e.beamProbeLock.Unlock()
	if _, attached := e.beamProbeLinks[fileID]; attached {
		return nil
	}
	if e.beamBIFEntryProgram == nil {
		return fmt.Errorf("BEAM BIF probes are unavailable")
	}
	symbol, err := beamBIFSymbol(path)
	if err != nil {
		return err
	}
	executable, err := link.OpenExecutable(path)
	if err != nil {
		return fmt.Errorf("open BEAM executable: %w", err)
	}
	entry, err := executable.Uprobe(symbol, e.beamBIFEntryProgram, nil)
	if err != nil {
		return fmt.Errorf("attach BEAM BIF entry probe: %w", err)
	}
	e.beamProbeLinks[fileID] = &beamBIFProbeLinks{entry: entry}
	return nil
}

func (e *ebpfMapsImpl) DetachBEAMBIF(fileID uint64) {
	e.beamProbeLock.Lock()
	defer e.beamProbeLock.Unlock()
	if probes, attached := e.beamProbeLinks[fileID]; attached {
		probes.close()
		delete(e.beamProbeLinks, fileID)
	}
}

func (e *ebpfMapsImpl) CloseBEAMProbes() {
	e.beamProbeLock.Lock()
	defer e.beamProbeLock.Unlock()
	for fileID, probes := range e.beamProbeLinks {
		probes.close()
		delete(e.beamProbeLinks, fileID)
	}
	for fileID, probes := range e.beamDirtyLinks {
		probes.close()
		delete(e.beamDirtyLinks, fileID)
	}
}

func (e *ebpfMapsImpl) AttachBEAMDirtyNIF(fileID uint64, path string) error {
	e.beamProbeLock.Lock()
	defer e.beamProbeLock.Unlock()
	if _, attached := e.beamDirtyLinks[fileID]; attached {
		return nil
	}
	if e.beamDirtyEntryProgram == nil {
		return fmt.Errorf("BEAM dirty NIF probes are unavailable")
	}
	executable, err := link.OpenExecutable(path)
	if err != nil {
		return fmt.Errorf("open BEAM executable: %w", err)
	}
	entry, err := executable.Uprobe("erts_call_dirty_nif", e.beamDirtyEntryProgram, nil)
	if err != nil {
		return fmt.Errorf("attach BEAM dirty NIF entry probe: %w", err)
	}
	e.beamDirtyLinks[fileID] = &beamDirtyProbeLinks{entry: entry}
	return nil
}

func (e *ebpfMapsImpl) DetachBEAMDirtyNIF(fileID uint64) {
	e.beamProbeLock.Lock()
	defer e.beamProbeLock.Unlock()
	if probes, attached := e.beamDirtyLinks[fileID]; attached {
		probes.close()
		delete(e.beamDirtyLinks, fileID)
	}
}
