// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"errors"
	"fmt"
	"strconv"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// The root tests in this file load the iterator and freplace fixtures,
// attach them, check the link through its fdinfo and destroy it, like the
// tests of attach_fd_load_test.go.

// Kernel releases from which a link fdinfo prints a field: the iterator
// target name since 5.10 and the tracing link target program and BTF ids
// since 6.5. An older kernel without the field skips the check.
var (
	iterTargetNameSince  = kernelVersion(5, 10, 0)
	tracingTargetIDSince = kernelVersion(6, 5, 0)
)

// TestBpfProgramAttachIter loads iter.bpf.o, whose iter/bpf_map program the
// load resolves to the kernel's bpf_iter_bpf_map function, attaches it with
// nil options, with nil and empty link info and through the section name,
// and checks the iter link, whose fdinfo must name the bpf_map target. It
// skips with the load error when the kernel BTF has no bpf_iter_bpf_map.
func TestBpfProgramAttachIter(t *testing.T) {
	obj := loadIterObject(t, "iter.bpf.o", "dump_bpf_map", "")
	defer BpfObjectClose(obj)
	prog := findProgram(t, obj, "dump_bpf_map")

	attaches := []struct {
		name   string
		attach func() (*BpfLink, error)
	}{
		{"nil options", func() (*BpfLink, error) { return BpfProgramAttachIter(prog, nil) }},
		{"nil link info", func() (*BpfLink, error) { return BpfProgramAttachIter(prog, &BpfIterOpts{}) }},
		{"empty link info", func() (*BpfLink, error) { return BpfProgramAttachIter(prog, &BpfIterOpts{LinkInfo: []byte{}}) }},
		{"section", func() (*BpfLink, error) { return BpfProgramAttach(prog) }},
	}
	for _, a := range attaches {
		t.Run(a.name, func(t *testing.T) {
			checkIterAttach(t, prog, a.attach)
		})
	}
}

// TestBpfProgramAttachIterBare loads iter_bare.bpf.o, whose program has the
// bare iter section, after BpfProgramSetAttachTarget names the bpf_map
// iterator, and attaches it through the section name, which gets the
// default iterator. Without the setter the load fails with EINVAL, because
// the section names no target. It skips with the load error when the kernel
// BTF has no bpf_iter_bpf_map.
func TestBpfProgramAttachIterBare(t *testing.T) {
	checkBareLoadRefused(t, "iter_bare.bpf.o", "dump_bare", 0)

	obj := loadIterObject(t, "iter_bare.bpf.o", "dump_bare", "bpf_map")
	defer BpfObjectClose(obj)
	prog := findProgram(t, obj, "dump_bare")
	checkIterAttach(t, prog, func() (*BpfLink, error) { return BpfProgramAttach(prog) })
}

// checkIterAttach attaches prog with attach and checks the iter link: its
// type, program and the bpf_map target name.
func checkIterAttach(t *testing.T, prog *BpfProgram, attach func() (*BpfLink, error)) {
	t.Helper()

	link, err := attach()
	if err != nil {
		skipIfNotPermitted(t, err)
		t.Fatalf("attach: %v", err)
	}
	checkLinkFdinfo(t, link, prog, "iter", nil)
	info := fdinfo(t, BpfLinkFD(link))
	destroyLink(t, link)
	if target := linkFdinfoField(t, info, "target_name", iterTargetNameSince); target != "bpf_map" {
		t.Errorf("target_name = %q, want bpf_map", target)
	}
}

// loadIterObject opens the iterator fixture object, names the target of
// its program prog with BpfProgramSetAttachTarget when target is not empty,
// and loads it. A kernel whose BTF has no bpf_iter_bpf_map function makes
// the load fail, and the test skips with the load error.
func loadIterObject(t *testing.T, object, prog, target string) *BpfObject {
	t.Helper()

	path := progsDir + "/" + object
	obj, err := BpfObjectOpenFile(path, nil)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	if target != "" {
		if err := BpfProgramSetAttachTarget(findProgram(t, obj, prog), 0, target); err != nil {
			BpfObjectClose(obj)
			skipIfKernelLacks(t, "the bpf_map iterator", kernelFuncHas(t, "bpf_iter_bpf_map"), err)
			t.Fatalf("set attach target %q: %v", target, err)
		}
	}
	if err := BpfObjectLoad(obj); err != nil {
		BpfObjectClose(obj)
		skipIfNotPermitted(t, err)
		skipIfKernelLacks(t, "the bpf_map iterator", kernelFuncHas(t, "bpf_iter_bpf_map"), err)
		t.Fatalf("load %s: %v", path, err)
	}
	return obj
}

// TestBpfProgramAttachFreplace loads xdp.bpf.o as the target and
// freplace.bpf.o against its xdp_pass function, and attaches the freplace
// program in place of xdp_pass: with the target descriptor and
// function name, which sends the target and its BTF id through
// BPF_LINK_CREATE; without a target, which attaches to the load-time target;
// and through the section name. Each case loads xdp.bpf.o and
// freplace.bpf.o again: the kernel forgets the load-time target after the
// first attach, and a kernel that refuses the attach with ENOTSUPP keeps the
// refused extension on the target's trampoline and refuses every later
// extension of that target with EBUSY. The link must be a tracing link with
// attach type 0 whose fdinfo names the target program's id and the BTF id
// of xdp_pass in its BTF; kernels before 6.5 do not print those ids and skip
// that check. The target program must report the object's BTF id. It skips
// with the kernel's errno when the kernel BTF has no program extensions or
// the kernel cannot attach them, see checkFreplaceAttach.
//
// The target is not kprobe.bpf.o's handle_open: its void * argument is not
// the kprobe context type, so the kernel marks the function's BTF
// unreliable and refuses to replace it with "Cannot replace static
// functions".
func TestBpfProgramAttachFreplace(t *testing.T) {
	attaches := []struct {
		name     string
		loadName string
		attach   func(p *BpfProgram, targetFD int) (*BpfLink, error)
	}{
		{"target", "xdp_pass", func(p *BpfProgram, targetFD int) (*BpfLink, error) {
			return BpfProgramAttachFreplace(p, targetFD, "xdp_pass")
		}},
		{"no target", "", func(p *BpfProgram, _ int) (*BpfLink, error) { return BpfProgramAttachFreplace(p, 0, "") }},
		{"section", "", func(p *BpfProgram, _ int) (*BpfLink, error) { return BpfProgramAttach(p) }},
	}
	for _, a := range attaches {
		t.Run(a.name, func(t *testing.T) {
			target := loadTestObject(t, progsDir+"/xdp.bpf.o")
			defer BpfObjectClose(target)
			targetProg := findProgram(t, target, "xdp_pass")
			checkProgramBtfID(t, target, targetProg)
			fn := target.btf.Find("xdp_pass", btf.KindFunc)
			if fn == nil {
				t.Fatal("xdp.bpf.o BTF has no FUNC xdp_pass")
			}

			obj := loadFreplaceObject(t, "freplace.bpf.o", "replace_xdp", targetProg.fd, a.loadName)
			defer BpfObjectClose(obj)
			prog := findProgram(t, obj, "replace_xdp")
			attach := func(p *BpfProgram) (*BpfLink, error) { return a.attach(p, targetProg.fd) }
			checkFreplaceAttach(t, prog, attach, targetProg.id, fn.ID)
		})
	}
}

// TestBpfProgramAttachFreplaceBare loads freplace_bare.bpf.o, whose program
// has the bare freplace section, after BpfProgramSetAttachTarget names
// xdp_pass of the loaded xdp.bpf.o, and attaches it through the section name
// to that load-time target. With the target descriptor alone the load fails
// with EINVAL, because the section names no function to look up. It skips
// with the kernel's errno when the kernel BTF has no program extensions or
// the kernel cannot attach them, see checkFreplaceAttach.
func TestBpfProgramAttachFreplaceBare(t *testing.T) {
	target := loadTestObject(t, progsDir+"/xdp.bpf.o")
	defer BpfObjectClose(target)
	targetProg := findProgram(t, target, "xdp_pass")
	fn := target.btf.Find("xdp_pass", btf.KindFunc)
	if fn == nil {
		t.Fatal("xdp.bpf.o BTF has no FUNC xdp_pass")
	}

	checkBareLoadRefused(t, "freplace_bare.bpf.o", "replace_bare", targetProg.fd)

	obj := loadFreplaceObject(t, "freplace_bare.bpf.o", "replace_bare", targetProg.fd, "xdp_pass")
	defer BpfObjectClose(obj)
	prog := findProgram(t, obj, "replace_bare")
	checkFreplaceAttach(t, prog, func(p *BpfProgram) (*BpfLink, error) { return BpfProgramAttach(p) }, targetProg.id, fn.ID)
}

// checkFreplaceAttach attaches prog with attach and checks the tracing
// link: its type, program and attach type 0, and the target program id and
// the BTF id of the replaced function in its fdinfo. It skips when bpf() is
// not permitted, when the kernel BTF has no program extensions, and with
// ENOTSUPP (524), which a kernel that cannot patch the target returns: arm64
// has no BPF trampoline or text poke before 6.0.
func checkFreplaceAttach(t *testing.T, prog *BpfProgram, attach func(*BpfProgram) (*BpfLink, error), targetID, btfID uint32) {
	t.Helper()

	link, err := attach(prog)
	if err != nil {
		skipIfNotPermitted(t, err)
		skipIfKernelLacks(t, "program extensions", kernelEnumHas(t, "bpf_prog_type", "BPF_PROG_TYPE_EXT"), err)
		if errors.Is(err, enotsupp) {
			t.Skipf("kernel cannot attach program extensions, no BPF trampoline or text poke as on arm64 before 6.0: %v", err)
		}
		t.Fatalf("attach: %v", err)
	}
	checkLinkFdinfo(t, link, prog, "tracing", map[string]string{"attach_type": "0"})
	info := fdinfo(t, BpfLinkFD(link))
	destroyLink(t, link)

	want := map[string]uint32{"target_obj_id": targetID, "target_btf_id": btfID}
	for _, key := range []string{"target_obj_id", "target_btf_id"} {
		if got := linkFdinfoField(t, info, key, tracingTargetIDSince); got != strconv.FormatUint(uint64(want[key]), 10) {
			t.Errorf("%s = %q, want %d", key, got, want[key])
		}
	}
}

// loadFreplaceObject opens the freplace fixture object, sets the attach
// target of its program prog to the program targetFD and the function name,
// empty for the section target, and loads it. It skips with the load error
// when bpf() is not permitted or the kernel BTF has no program extensions.
func loadFreplaceObject(t *testing.T, object, prog string, targetFD int, name string) *BpfObject {
	t.Helper()

	path := progsDir + "/" + object
	obj, err := BpfObjectOpenFile(path, nil)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	if err := BpfProgramSetAttachTarget(findProgram(t, obj, prog), targetFD, name); err != nil {
		BpfObjectClose(obj)
		t.Fatalf("set attach target %d %q: %v", targetFD, name, err)
	}
	if err := BpfObjectLoad(obj); err != nil {
		BpfObjectClose(obj)
		skipIfNotPermitted(t, err)
		skipIfKernelLacks(t, "program extensions", kernelEnumHas(t, "bpf_prog_type", "BPF_PROG_TYPE_EXT"), err)
		t.Fatalf("load %s: %v", path, err)
	}
	return obj
}

// checkBareLoadRefused opens object, gives its bare-section program prog the
// attach program descriptor targetFD alone, when it is not 0, and requires
// the load to fail with EINVAL: the section names no target and no function
// was set.
func checkBareLoadRefused(t *testing.T, object, prog string, targetFD int) {
	t.Helper()

	obj := openProg(t, object)
	if targetFD != 0 {
		if err := BpfProgramSetAttachTarget(findProgram(t, obj, prog), targetFD, ""); err != nil {
			t.Fatalf("set attach target %d: %v", targetFD, err)
		}
	}
	err := BpfObjectLoad(obj)
	skipIfNotPermitted(t, err)
	if !errors.Is(err, unix.EINVAL) {
		t.Fatalf("load %s without a function = %v, want EINVAL", object, err)
	}
}

// TestResolveAttachBTFIDEmptyProgTarget checks that an EXT program whose
// section target after the slash is empty looks the empty name up in the
// BTF of its attach program, as libbpf's program-BTF lookup does, and fails
// with ENOENT, not EINVAL. The attach program is xdp_pass of xdp.bpf.o.
func TestResolveAttachBTFIDEmptyProgTarget(t *testing.T) {
	target := loadTestObject(t, progsDir+"/xdp.bpf.o")
	defer BpfObjectClose(target)

	prog := &BpfProgram{name: "replace_empty", sectionName: "freplace/", attachProg: true,
		progType: BPF_PROG_TYPE_EXT, attachProgFD: findProgram(t, target, "xdp_pass").fd}
	if err := resolveAttachBTFID(prog); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("resolveAttachBTFID = %v, want ENOENT", err)
	}
	if prog.attachBTFID != 0 {
		t.Fatalf("attach BTF id = %d after a failed resolve, want 0", prog.attachBTFID)
	}
}

// checkProgramBtfID requires the loaded prog of obj to report, through
// BpfProgramInfo, a nonzero BTF id that is the id of the object's BTF
// descriptor.
func checkProgramBtfID(t *testing.T, obj *BpfObject, prog *BpfProgram) {
	t.Helper()

	info, err := BpfProgramInfo(prog)
	if err != nil {
		t.Fatalf("program info: %v", err)
	}
	if info.BtfID == 0 {
		t.Fatalf("program %s BTF id = 0, want the object's BTF", prog.name)
	}
	if obj.btfFD < 0 {
		t.Fatalf("object BTF descriptor = %d after the load", obj.btfFD)
	}
	btfInfo, err := sys.BtfInfoByFD(obj.btfFD, nil, nil)
	if err != nil {
		t.Fatalf("object BTF info: %v", err)
	}
	if info.BtfID != btfInfo.ID {
		t.Fatalf("program %s BTF id = %d, want the object's BTF id %d", prog.name, info.BtfID, btfInfo.ID)
	}
}

// linkFdinfoField returns the field key of the link fdinfo info. A missing
// field fails the test on kernels from since on, which print it, and skips
// the test on older ones, naming the gap.
func linkFdinfoField(t *testing.T, info map[string]string, key string, since uint32) string {
	t.Helper()

	value, ok := info[key]
	if ok {
		return value
	}
	release := fmt.Sprintf("%d.%d", since>>16, since>>8&0xff)
	if getKernelVersion() >= since {
		t.Fatalf("link fdinfo has no %s, which kernels from %s print", key, release)
	}
	t.Skipf("kernel %s link fdinfo has no %s: kernels before %s do not print it", kernelRelease(t), key, release)
	return ""
}

// kernelFuncHas reports whether the running kernel's BTF has the function
// name. It fails the test when the kernel BTF cannot be read, like
// kernelEnumHas.
func kernelFuncHas(t *testing.T, name string) bool {
	t.Helper()

	kernel, err := vmlinuxBTF()
	if err != nil {
		t.Fatalf("read kernel BTF for function %s: %v", name, err)
	}
	return kernel.Find(name, btf.KindFunc) != nil
}
