// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"golang.org/x/sys/unix"
)

// The kernel symbols the .ksyms fixtures resolve.
const (
	ksymPerCPU = "bpf_prog_active"
	ksymTask   = "init_task"
	ksymLock   = "bpf_rcu_read_lock"
	ksymUnlock = "bpf_rcu_read_unlock"
)

// TestKsymsLoadTyped links link_ksyms.bpf.o, loads it, attaches
// handle_ksyms to do_sys_openat2 and opens a file. The program reads
// bpf_prog_active through the typed per-CPU .ksyms variable between
// bpf_rcu_read_lock and bpf_rcu_read_unlock kfunc calls. The kprobe path
// raises bpf_prog_active to 1 on the CPU around the program, so the program
// must see 1. The externs must resolve to the kernel's BTF IDs, and the
// verifier accepting the kfunc calls proves their encoding.
//
// It needs root or CAP_BPF and skips otherwise. It skips on a kernel without
// BTF, without the per-CPU variable or the kfuncs in its BTF, as on 5.10,
// or whose verifier refuses these kfuncs in a kprobe program.
func TestKsymsLoadTyped(t *testing.T) {
	kernel := requireKernelBTF(t)
	wantIDs := map[string]uint32{
		ksymPerCPU: kernelTypeID(t, kernel, ksymPerCPU, btf.KindVar),
		ksymLock:   kernelTypeID(t, kernel, ksymLock, btf.KindFunc),
		ksymUnlock: kernelTypeID(t, kernel, ksymUnlock, btf.KindFunc),
	}

	path := linkObjects(t, ksymsProg)
	obj, err := BpfObjectOpenFile(path, nil)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer BpfObjectClose(obj)
	if err := BpfObjectLoad(obj); err != nil {
		skipKsymsLoad(t, err)
		t.Fatalf("load %s: %v", path, err)
	}

	gotIDs := map[string]uint32{}
	for _, ext := range obj.externs {
		gotIDs[ext.name] = ext.ksym.kernelBtfID
		if !ext.isSet || ext.ksym.kernelBtfObjFD != 0 || ext.ksym.btfFdIdx != 0 {
			t.Errorf("%s = %+v, want a vmlinux resolution", ext.name, ext.ksym)
		}
	}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("kernel BTF IDs = %v, want %v", gotIDs, wantIDs)
	}

	attachKprobes(t, obj, map[string]string{"handle_ksyms": "do_sys_openat2"})
	triggerOpen(t)
	if got := bssU32(t, obj, path, "ksym_active"); got != 1 {
		t.Fatalf("ksym_active = %d, want 1: the program did not read bpf_prog_active", got)
	}
}

// TestKsymsLoadAddr links link_ksyms_addr.bpf.o, loads it, attaches
// handle_ksyms_addr and opens a file. The program stores the addresses of
// its typeless .ksyms externs, which must be the /proc/kallsyms addresses.
// Before the load, which resolves those externs from /proc/kallsyms, it
// skips when /proc/kallsyms lacks either symbol, as a kernel without
// CONFIG_KALLSYMS_ALL lists no data symbols, or hides its address. It needs
// root or CAP_BPF and skips otherwise.
func TestKsymsLoadAddr(t *testing.T) {
	path := linkObjects(t, ksymsAddrProg)

	want := kallsymsAddrs(t, ksymPerCPU, ksymTask)
	for _, name := range []string{ksymPerCPU, ksymTask} {
		addr, ok := want[name]
		if !ok {
			t.Skipf("/proc/kallsyms has no %s: the kernel lists data symbols only with CONFIG_KALLSYMS_ALL", name)
		}
		if addr == 0 {
			t.Skipf("/proc/kallsyms hides %s", name)
		}
	}

	obj := loadTestObject(t, path)
	defer BpfObjectClose(obj)

	attachKprobes(t, obj, map[string]string{"handle_ksyms_addr": "do_sys_openat2"})
	triggerOpen(t)
	got := bssU64s(t, obj, path, "ksym_addrs", 2)
	if wantAddrs := []uint64{want[ksymPerCPU], want[ksymTask]}; !reflect.DeepEqual(got, wantAddrs) {
		t.Fatalf("ksym_addrs = %#x, want %#x", got, wantAddrs)
	}
}

// TestKsymsLoadWeak links link_ksyms_weak.bpf.o, loads it, attaches
// handle_ksyms_weak and opens a file. The weak externs the kernel lacks
// read as zero: the typed variable and the kernel function do not exist and
// the typeless variable has address 0. The poisoned call to the missing
// function is dead code, so the verifier accepts the program. bpf_prog_active
// has its kallsyms address. It needs root or CAP_BPF and skips otherwise,
// and skips without kernel BTF, which the typed externs need.
func TestKsymsLoadWeak(t *testing.T) {
	requireKernelBTF(t)
	path := linkObjects(t, ksymsWeakProg)
	obj := loadTestObject(t, path)
	defer BpfObjectClose(obj)

	if ext := findExternByName(obj.externs, "gobpfgo_missing_kfunc"); ext.isSet {
		t.Fatalf("gobpfgo_missing_kfunc resolved to %+v", ext.ksym)
	}
	active := kallsymsAddrs(t, ksymPerCPU)[ksymPerCPU]

	attachKprobes(t, obj, map[string]string{"handle_ksyms_weak": "do_sys_openat2"})
	triggerOpen(t)
	got := bssU64s(t, obj, path, "ksym_weak", 4)
	if want := []uint64{0, 0, 0, active}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ksym_weak = %#x, want %#x", got, want)
	}
}

// TestKsymsLoadMissingKfunc loads kfunc_missing.bpf.o, whose program calls
// a weak kernel function no kernel has without checking that it exists. The
// loader poisons the call with the extern's index, the verifier reaches it
// and the program fails to load with EINVAL. The log fixup replaces the
// poisoned call and the verifier's error for it with the instruction index
// and the kernel function's name. It needs root or CAP_BPF and skips
// otherwise, and skips without kernel BTF, which the extern needs.
func TestKsymsLoadMissingKfunc(t *testing.T) {
	requireKernelBTF(t)
	obj := openProg(t, "kfunc_missing.bpf.o")
	err := BpfObjectLoad(obj)
	skipIfNotPermitted(t, err)

	var lerr *Error
	if !errors.As(err, &lerr) || lerr.Op != "bpf_prog_load" || !errors.Is(err, unix.EINVAL) {
		t.Fatalf("load: %v, want a bpf_prog_load EINVAL for the poisoned kfunc call", err)
	}
	if ext := findExternByName(obj.externs, "gobpfgo_missing_kfunc"); ext.isSet {
		t.Fatalf("gobpfgo_missing_kfunc resolved to %+v", ext.ksym)
	}
	p := BpfObjectFindProgramByName(obj, "handle_kfunc_missing")
	if len(p.relocs) != 1 {
		t.Fatalf("%d relocations, want the kfunc call's", len(p.relocs))
	}
	extIdx := slices.IndexFunc(obj.externs, func(e externDesc) bool { return e.name == "gobpfgo_missing_kfunc" })
	want := fmt.Sprintf("%d: <invalid kfunc call>\nkfunc 'gobpfgo_missing_kfunc' is referenced but wasn't resolved\n",
		p.relocs[0].Offset/bpfInsnLength)
	if !strings.HasPrefix(lerr.Log, "handle_kfunc_missing: ") || !strings.Contains(lerr.Log, want) {
		t.Errorf("load log = %q, want the handle_kfunc_missing log with %q", lerr.Log, want)
	}
	if poison := fmt.Sprintf("unknown#%d", poisonCallKfuncBase+extIdx); strings.Contains(lerr.Log, poison) {
		t.Errorf("load log = %q, still has the poisoned call %s", lerr.Log, poison)
	}
	if BpfProgramFD(p) != -1 {
		t.Errorf("program descriptor %d after the failed load", BpfProgramFD(p))
	}
}

// requireKernelBTF returns the running kernel's BTF, or skips the test when
// the kernel has none.
func requireKernelBTF(t *testing.T) *btf.Spec {
	t.Helper()

	kernel, err := loadKernelBTF()
	if errors.Is(err, os.ErrNotExist) {
		t.Skipf("kernel BTF unavailable: %v", err)
	}
	if err != nil {
		t.Fatalf("loadKernelBTF: %v", err)
	}
	return kernel
}

// kernelTypeID returns the vmlinux BTF ID of the named VAR or FUNC, or skips
// the test when the kernel does not have it.
func kernelTypeID(t *testing.T, kernel *btf.Spec, name string, kind btf.Kind) uint32 {
	t.Helper()

	id := findByNameKind(kernel, 1, name, kind)
	if id == 0 {
		t.Skipf("kernel BTF has no %s %s", kind, name)
	}
	return id
}

// skipKsymsLoad skips the test when the load failed for lack of privileges
// or because the verifier does not allow the kfuncs in this program type.
func skipKsymsLoad(t *testing.T, err error) {
	t.Helper()

	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("bpf() not permitted: %v", err)
	}
	var e *Error
	if errors.As(err, &e) && strings.Contains(e.Log, "calling kernel function") {
		t.Skipf("kernel does not allow the kfuncs here: %v", err)
	}
}

// kallsymsAddrs reads /proc/kallsyms and returns the first address of each
// named symbol, 0 for a missing one.
func kallsymsAddrs(t *testing.T, names ...string) map[string]uint64 {
	t.Helper()

	f, err := os.Open(kallsymsPath)
	if err != nil {
		t.Fatalf("open %s: %v", kallsymsPath, err)
	}
	defer f.Close()

	addrs := make(map[string]uint64, len(names))
	seen := map[string]bool{}
	err = kallsymsParse(f, func(addr uint64, _ byte, name string) error {
		for _, want := range names {
			if name == want && !seen[name] {
				addrs[name], seen[name] = addr, true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read %s: %v", kallsymsPath, err)
	}
	return addrs
}

// bssU32 reads the 32-bit .bss variable name of the loaded object linked at
// path.
func bssU32(t *testing.T, obj *BpfObject, path, name string) uint32 {
	t.Helper()

	off := int(datasecVarOffset(t, parseFileBTF(t, path), ".bss", name))
	bss := lookupGlobal(t, globalDataMap(t, obj, ".bss"))
	if off+4 > len(bss) {
		t.Fatalf("%s at %d is outside the %d-byte .bss", name, off, len(bss))
	}
	return binary.NativeEndian.Uint32(bss[off:])
}

// bssU64s reads the n 64-bit values of the .bss array name of the loaded
// object linked at path.
func bssU64s(t *testing.T, obj *BpfObject, path, name string, n int) []uint64 {
	t.Helper()

	off := int(datasecVarOffset(t, parseFileBTF(t, path), ".bss", name))
	bss := lookupGlobal(t, globalDataMap(t, obj, ".bss"))
	if off+8*n > len(bss) {
		t.Fatalf("%s at %d is outside the %d-byte .bss", name, off, len(bss))
	}
	values := make([]uint64, n)
	for i := range values {
		values[i] = binary.NativeEndian.Uint64(bss[off+8*i:])
	}
	return values
}
