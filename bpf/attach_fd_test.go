// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package bpf_test

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/gobpfgo/gobpfgo/bpf"
	"github.com/gobpfgo/gobpfgo/internal/btf"
	"github.com/gobpfgo/gobpfgo/internal/elf"
	"github.com/gobpfgo/gobpfgo/libbpf"
	"golang.org/x/sys/unix"
)

// TestAttachFD attaches through the object layer to a cgroup, a network
// namespace, an interface and a sockmap: the cgroup_skb/ingress program of
// cgroup.bpf.o with AttachCgroup and AttachCgroupOpts to the cgroup v2 root,
// the flow dissector of netns.bpf.o to the test's network namespace,
// xdp.bpf.o to the loopback interface, and the sk_msg program of
// sockmap.bpf.o to a new sockmap. Each Link must have a descriptor, which
// Destroy releases. It needs root and skips when the kernel refuses bpf() or
// the target is taken, and skips the sockmap with the kernel's errno when
// the kernel BTF has no sockmap link type.
func TestAttachFD(t *testing.T) {
	tests := []struct {
		name    string
		object  string
		program string
		attach  func(t *testing.T, p *bpf.Program) (*bpf.Link, error)
	}{
		{"cgroup", "cgroup.bpf.o", "cgroup_ingress", func(t *testing.T, p *bpf.Program) (*bpf.Link, error) {
			return p.AttachCgroup(openCgroupV2Root(t))
		}},
		{"cgroup options", "cgroup.bpf.o", "cgroup_ingress", func(t *testing.T, p *bpf.Program) (*bpf.Link, error) {
			return p.AttachCgroupOpts(openCgroupV2Root(t), &libbpf.BpfCgroupOpts{})
		}},
		{"netns", "netns.bpf.o", "dissect", func(t *testing.T, p *bpf.Program) (*bpf.Link, error) {
			netns, err := os.Open("/proc/self/ns/net")
			if err != nil {
				t.Fatalf("open network namespace: %v", err)
			}
			t.Cleanup(func() { netns.Close() })
			return p.AttachNetns(int(netns.Fd()))
		}},
		{"xdp", "xdp.bpf.o", "xdp_pass", func(t *testing.T, p *bpf.Program) (*bpf.Link, error) {
			lo, err := net.InterfaceByName("lo")
			if err != nil {
				t.Fatalf("loopback interface: %v", err)
			}
			return p.AttachXDP(lo.Index)
		}},
		{"sockmap", "sockmap.bpf.o", "msg_pass", func(t *testing.T, p *bpf.Program) (*bpf.Link, error) {
			mapFD, err := libbpf.BpfMapCreate(libbpf.BPF_MAP_TYPE_SOCKMAP, "gobpfgo_sockmap", 4, 4, 1, nil)
			if err != nil {
				skipIfNotPermitted(t, "sockmap create", err)
				t.Fatalf("create sockmap: %v", err)
			}
			t.Cleanup(func() { unix.Close(mapFD) })

			link, err := p.AttachSockmap(mapFD)
			if err != nil {
				skipIfNotPermitted(t, "sockmap attach", err)
				if !kernelEnumHas(t, "bpf_link_type", "BPF_LINK_TYPE_SOCKMAP") {
					t.Skipf("kernel lacks sockmap links: %v", err)
				}
			}
			return link, err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj, err := bpf.OpenFile(progsDir+"/"+tt.object, nil)
			if err != nil {
				t.Fatalf("OpenFile: %v", err)
			}
			defer obj.Close()
			if err := obj.Load(); err != nil {
				skipIfNotPermitted(t, "bpf()", err)
				t.Fatalf("Load: %v", err)
			}

			link, err := tt.attach(t, obj.Program(tt.program))
			if err != nil {
				skipIfNotPermitted(t, tt.name+" attach", err)
				if errors.Is(err, unix.EEXIST) || errors.Is(err, unix.EBUSY) {
					t.Skipf("%s target is taken: %v", tt.name, err)
				}
				t.Fatalf("attach: %v", err)
			}
			if link.FD() < 0 {
				t.Fatalf("link FD = %d", link.FD())
			}
			link.Destroy()
			if link.FD() != -1 {
				t.Errorf("link FD after Destroy = %d, want -1", link.FD())
			}
		})
	}
}

// TestAttachCgroupPlacement places a cgroup link relative to another through
// the object layer. It loads cgroup.bpf.o twice, attaches the
// cgroup_skb/ingress program of the first object to the cgroup v2 root as
// the anchor link, and attaches the same program of the second object before
// it with BPF_F_BEFORE|BPF_F_LINK and the anchor's link descriptor as
// RelativeFD. The anchor takes no flags: the kernels with cgroup revisions
// refuse BPF_F_LINK without BPF_F_BEFORE or BPF_F_AFTER with EINVAL. Destroy
// must release both links. It needs root, and skips with the kernel's errno
// when the kernel BTF shows no multi-program cgroup attachment, whose
// kernels refuse link flags.
func TestAttachCgroupPlacement(t *testing.T) {
	cgroupFD := openCgroupV2Root(t)
	anchorProg := loadCgroupIngress(t)
	prog := loadCgroupIngress(t)

	anchor, err := anchorProg.AttachCgroup(cgroupFD)
	if err != nil {
		skipIfNotPermitted(t, "cgroup attach", err)
		t.Fatalf("attach anchor: %v", err)
	}
	anchorFD := anchor.FD()
	before, err := prog.AttachCgroupOpts(cgroupFD, &libbpf.BpfCgroupOpts{
		Flags:      libbpf.BPF_F_BEFORE | libbpf.BPF_F_LINK,
		RelativeFD: anchorFD,
	})
	if err != nil {
		anchor.Destroy()
		if !kernelStructHasMember(t, "cgroup_bpf", "revisions") {
			t.Skipf("kernel lacks cgroup program revisions: %v", err)
		}
		t.Fatalf("attach before anchor link fd %d: %v", anchorFD, err)
	}

	for _, l := range []struct {
		name string
		link *bpf.Link
	}{{"before", before}, {"anchor", anchor}} {
		if l.link.FD() < 0 {
			t.Errorf("%s link FD = %d", l.name, l.link.FD())
		}
		l.link.Destroy()
		if l.link.FD() != -1 {
			t.Errorf("%s link FD after Destroy = %d, want -1", l.name, l.link.FD())
		}
	}
}

// TestAttachIter attaches the iter/bpf_map program of iter.bpf.o through the
// object layer with nil options, nil link info and empty link info. Each
// Link must be an iter link of the program whose fdinfo names the bpf_map
// target, and Destroy must release it. It needs root and skips when the
// kernel refuses bpf(), and with the load error when the kernel BTF has no
// bpf_iter_bpf_map function.
func TestAttachIter(t *testing.T) {
	obj, err := bpf.OpenFile(progsDir+"/iter.bpf.o", nil)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer obj.Close()
	if err := obj.Load(); err != nil {
		skipIfNotPermitted(t, "bpf()", err)
		if kernelBTF(t).Find("bpf_iter_bpf_map", btf.KindFunc) == nil {
			t.Skipf("kernel lacks the bpf_map iterator: %v", err)
		}
		t.Fatalf("Load: %v", err)
	}
	prog := obj.Program("dump_bpf_map")

	opts := map[string]*libbpf.BpfIterOpts{
		"nil options":     nil,
		"nil link info":   {},
		"empty link info": {LinkInfo: []byte{}},
	}
	for name, opts := range opts {
		t.Run(name, func(t *testing.T) {
			link, err := prog.AttachIter(opts)
			if err != nil {
				skipIfNotPermitted(t, "iter attach", err)
				t.Fatalf("AttachIter: %v", err)
			}
			info := checkLinkDestroy(t, link, "iter", prog, nil)
			if target := fdinfoField(t, info, "target_name", 5, 10); target != "bpf_map" {
				t.Errorf("target_name = %q, want bpf_map", target)
			}
		})
	}
}

// TestAttachFreplace loads xdp.bpf.o as the target, whose xdp_pass must
// report a BTF id through Info, sets the freplace program of freplace.bpf.o
// to the target's descriptor with SetAttachTarget, loads it, and attaches
// it with AttachFreplace in place of xdp_pass: with the target's descriptor
// and function name, and without a target, which attaches to the load-time
// target. Each case loads xdp.bpf.o and freplace.bpf.o again: the kernel
// forgets the load-time target after the first attach, and a kernel that
// refuses the attach with ENOTSUPP keeps the refused extension on the
// target's trampoline and refuses every later extension of that target with
// EBUSY. Each Link must be a tracing link of the program with attach type 0
// whose fdinfo names the target program's id and the BTF id of xdp_pass,
// which kernels before 6.5 do not print, and Destroy must release it. It
// needs root and skips when the kernel refuses bpf(), and with the kernel's
// errno when the kernel BTF has no program extensions or the kernel cannot
// attach them, see skipIfKernelLacksExt.
func TestAttachFreplace(t *testing.T) {
	funcID := objectFuncID(t, progsDir+"/xdp.bpf.o", "xdp_pass")

	attaches := map[string]func(p *bpf.Program, targetFD int) (*bpf.Link, error){
		"target":    func(p *bpf.Program, targetFD int) (*bpf.Link, error) { return p.AttachFreplace(targetFD, "xdp_pass") },
		"no target": func(p *bpf.Program, _ int) (*bpf.Link, error) { return p.AttachFreplace(0, "") },
	}
	for name, attach := range attaches {
		t.Run(name, func(t *testing.T) {
			targetFD, targetInfo := loadFreplaceTarget(t)
			prog := loadFreplace(t, targetFD)
			link, err := attach(prog, targetFD)
			if err != nil {
				skipIfNotPermitted(t, "freplace attach", err)
				skipIfKernelLacksExt(t, err)
				t.Fatalf("AttachFreplace: %v", err)
			}
			info := checkLinkDestroy(t, link, "tracing", prog, map[string]string{"attach_type": "0"})
			want := map[string]uint32{"target_obj_id": targetInfo.ID, "target_btf_id": funcID}
			for _, key := range []string{"target_obj_id", "target_btf_id"} {
				if got := fdinfoField(t, info, key, 6, 5); got != strconv.FormatUint(uint64(want[key]), 10) {
					t.Errorf("%s = %q, want %d", key, got, want[key])
				}
			}
		})
	}
}

// loadFreplaceTarget loads xdp.bpf.o, closed when the test ends, and
// returns the descriptor and info of its xdp_pass program, which must report
// the BTF id xdp.bpf.o was loaded with. It skips when the kernel refuses
// bpf().
func loadFreplaceTarget(t *testing.T) (int, *libbpf.BpfProgInfo) {
	t.Helper()

	target, err := bpf.OpenFile(progsDir+"/xdp.bpf.o", nil)
	if err != nil {
		t.Fatalf("OpenFile target: %v", err)
	}
	t.Cleanup(func() { target.Close() })
	if err := target.Load(); err != nil {
		skipIfNotPermitted(t, "bpf()", err)
		t.Fatalf("Load target: %v", err)
	}
	prog := target.Program("xdp_pass")
	info, err := prog.Info()
	if err != nil {
		t.Fatalf("target Info: %v", err)
	}
	if info.BtfID == 0 {
		t.Fatal("target BtfID = 0, want the BTF xdp.bpf.o was loaded with")
	}
	return prog.FD(), info
}

// loadFreplace opens freplace.bpf.o, closed when the test ends, sets its
// program's attach target to the program targetFD with SetAttachTarget,
// loads it, and returns the program, which no longer takes a target. It
// skips when the kernel refuses bpf() or has no program extensions.
func loadFreplace(t *testing.T, targetFD int) *bpf.Program {
	t.Helper()

	obj, err := bpf.OpenFile(progsDir+"/freplace.bpf.o", nil)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	t.Cleanup(func() { obj.Close() })
	prog := obj.Program("replace_xdp")
	if err := prog.SetAttachTarget(targetFD, ""); err != nil {
		t.Fatalf("SetAttachTarget: %v", err)
	}
	if err := obj.Load(); err != nil {
		skipIfNotPermitted(t, "bpf()", err)
		skipIfKernelLacksExt(t, err)
		t.Fatalf("Load: %v", err)
	}
	if err := prog.SetAttachTarget(targetFD, ""); err == nil {
		t.Error("SetAttachTarget after Load succeeded, want the core EINVAL error")
	}
	return prog
}

// skipIfKernelLacksExt skips with err when the running kernel's BTF has no
// BPF_PROG_TYPE_EXT, the program type of freplace programs, or when err is
// ENOTSUPP (524), which a kernel that cannot patch the target returns: arm64
// has no BPF trampoline or text poke before 6.0.
func skipIfKernelLacksExt(t *testing.T, err error) {
	t.Helper()

	if !kernelEnumHas(t, "bpf_prog_type", "BPF_PROG_TYPE_EXT") {
		t.Skipf("kernel lacks program extensions: %v", err)
	}
	if errors.Is(err, enotsupp) {
		t.Skipf("kernel cannot attach program extensions, no BPF trampoline or text poke as on arm64 before 6.0: %v", err)
	}
}

// checkLinkDestroy requires link to have a descriptor whose fdinfo names
// linkType, the id of prog and every field in want, destroys it, requires
// the descriptor to be released, and returns the fdinfo.
func checkLinkDestroy(t *testing.T, link *bpf.Link, linkType string, prog *bpf.Program, want map[string]string) map[string]string {
	t.Helper()

	if link.FD() < 0 {
		t.Fatalf("link FD = %d", link.FD())
	}
	info := fdinfo(t, link.FD())
	link.Destroy()
	if link.FD() != -1 {
		t.Errorf("link FD after Destroy = %d, want -1", link.FD())
	}

	progInfo, err := prog.Info()
	if err != nil {
		t.Fatalf("program Info: %v", err)
	}
	if got := info["link_type"]; got != linkType {
		t.Errorf("link_type = %q, want %q", got, linkType)
	}
	if got, id := info["prog_id"], strconv.FormatUint(uint64(progInfo.ID), 10); got != id {
		t.Errorf("prog_id = %q, want %s", got, id)
	}
	for key, value := range want {
		if got := info[key]; got != value {
			t.Errorf("%s = %q, want %q", key, got, value)
		}
	}
	return info
}

// fdinfo reads /proc/self/fdinfo of fd into a map of its fields.
func fdinfo(t *testing.T, fd int) map[string]string {
	t.Helper()

	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
	if err != nil {
		t.Fatalf("read fdinfo of %d: %v", fd, err)
	}
	fields := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			fields[key] = strings.TrimSpace(value)
		}
	}
	return fields
}

// fdinfoField returns the field key of the link fdinfo info. A missing
// field fails the test on kernels from major.minor on, which print it, and
// skips the test on older ones, naming the gap.
func fdinfoField(t *testing.T, info map[string]string, key string, major, minor int) string {
	t.Helper()

	value, ok := info[key]
	if ok {
		return value
	}
	release := kernelRelease(t)
	if kernelAtLeast(t, release, major, minor) {
		t.Fatalf("link fdinfo has no %s, which kernels from %d.%d print", key, major, minor)
	}
	t.Skipf("kernel %s link fdinfo has no %s: kernels before %d.%d do not print it", release, key, major, minor)
	return ""
}

// kernelRelease returns the running kernel release.
func kernelRelease(t *testing.T) string {
	t.Helper()

	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		t.Fatalf("read kernel release: %v", err)
	}
	return strings.TrimSpace(string(data))
}

// kernelAtLeast reports whether release, such as 6.18.63-3-lts, is
// major.minor or newer.
func kernelAtLeast(t *testing.T, release string, major, minor int) bool {
	t.Helper()

	var gotMajor, gotMinor int
	if _, err := fmt.Sscanf(release, "%d.%d", &gotMajor, &gotMinor); err != nil {
		t.Fatalf("parse kernel release %q: %v", release, err)
	}
	return gotMajor > major || gotMajor == major && gotMinor >= minor
}

// objectFuncID returns the id of the BTF FUNC name in the object file at
// path. The loader uploads the object BTF with its type ids unchanged, so
// it is the id in the loaded program's BTF too.
func objectFuncID(t *testing.T, path, name string) uint32 {
	t.Helper()

	o, err := elf.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	spec, err := btf.Parse(o.BTF, o.ByteOrder)
	if err != nil {
		t.Fatalf("parse %s BTF: %v", path, err)
	}
	fn := spec.Find(name, btf.KindFunc)
	if fn == nil {
		t.Fatalf("%s BTF has no FUNC %s", path, name)
	}
	return fn.ID
}

// loadCgroupIngress opens and loads a new copy of cgroup.bpf.o, closed when
// the test ends, and returns its cgroup_skb/ingress program. It skips the
// test when the kernel refuses bpf().
func loadCgroupIngress(t *testing.T) *bpf.Program {
	t.Helper()

	obj, err := bpf.OpenFile(progsDir+"/cgroup.bpf.o", nil)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	t.Cleanup(func() { obj.Close() })
	if err := obj.Load(); err != nil {
		skipIfNotPermitted(t, "bpf()", err)
		t.Fatalf("Load: %v", err)
	}
	return obj.Program("cgroup_ingress")
}

// kernelBTF reads and parses the running kernel's BTF. It fails the test
// when the BTF cannot be read, so that a missing BTF does not pass for a
// missing feature.
func kernelBTF(t *testing.T) *btf.Spec {
	t.Helper()

	data, err := os.ReadFile("/sys/kernel/btf/vmlinux")
	if err != nil {
		t.Fatalf("read kernel BTF: %v", err)
	}
	spec, err := btf.Parse(data, binary.NativeEndian)
	if err != nil {
		t.Fatalf("parse kernel BTF: %v", err)
	}
	return spec
}

// kernelEnumHas reports whether the running kernel's BTF has the enum
// enumName with the value valueName.
func kernelEnumHas(t *testing.T, enumName, valueName string) bool {
	t.Helper()

	enum := kernelBTF(t).Find(enumName, btf.KindEnum)
	if enum == nil {
		return false
	}
	for _, e := range enum.Enums {
		if e.Name == valueName {
			return true
		}
	}
	return false
}

// kernelStructHasMember reports whether the running kernel's BTF has the
// struct structName with the member member.
func kernelStructHasMember(t *testing.T, structName, member string) bool {
	t.Helper()

	kernel := kernelBTF(t)
	st := kernel.Find(structName, btf.KindStruct)
	return st != nil && kernel.Member(st, member) != nil
}

// openCgroupV2Root opens the root of the cgroup v2 hierarchy, at
// /sys/fs/cgroup on a unified system or /sys/fs/cgroup/unified on a hybrid
// one, and closes it when the test ends. It skips the test when neither is a
// cgroup v2 mount.
func openCgroupV2Root(t *testing.T) int {
	t.Helper()

	for _, path := range []string{"/sys/fs/cgroup", "/sys/fs/cgroup/unified"} {
		var fs unix.Statfs_t
		if err := unix.Statfs(path, &fs); err != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
			continue
		}
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		t.Cleanup(func() { unix.Close(fd) })
		return fd
	}
	t.Skip("no cgroup v2 hierarchy at /sys/fs/cgroup or /sys/fs/cgroup/unified")
	return -1
}
