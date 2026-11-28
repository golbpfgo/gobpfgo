// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package bpf_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/gobpfgo/gobpfgo/bpf"
	"github.com/gobpfgo/gobpfgo/libbpf"
)

// enotsupp is the kernel's ENOTSUPP (524), which a kernel before 5.14
// returns for LookupAndDelete on a hash map, and a kernel without a BPF
// trampoline for an freplace attach.
const enotsupp = syscall.Errno(524)

// u32Key and u64Value encode a 4-byte key and an 8-byte value in native byte
// order.
func u32Key(v uint32) []byte {
	return binary.NativeEndian.AppendUint32(nil, v)
}

func u64Value(v uint64) []byte {
	return binary.NativeEndian.AppendUint64(nil, v)
}

// loadObject opens path through the layer and loads it, skipping the test
// when the kernel refuses bpf() with EPERM or EACCES. The Object is closed
// when the test ends.
func loadObject(t *testing.T, path string) *bpf.Object {
	t.Helper()

	obj := openObject(t, path)
	if err := obj.Load(); err != nil {
		skipIfNotPermitted(t, "bpf()", err)
		t.Fatalf("Load %s: %v", path, err)
	}
	return obj
}

// mapKeys walks m with NextKey from the first key and returns the 4-byte keys
// it visits, sorted, stopping at the core ENOENT.
func mapKeys(t *testing.T, m *bpf.Map) []uint32 {
	t.Helper()

	var keys []uint32
	var cur []byte
	for range m.MaxEntries() + 1 {
		next := make([]byte, m.KeySize())
		err := m.NextKey(cur, next)
		if errors.Is(err, syscall.ENOENT) {
			slices.Sort(keys)
			return keys
		}
		if err != nil {
			t.Fatalf("NextKey after %x: %v", cur, err)
		}
		keys = append(keys, binary.NativeEndian.Uint32(next))
		cur = next
	}
	t.Fatalf("walk of %s did not end after %d keys", m.Name(), len(keys))
	return nil
}

// checkValue fails the test unless key holds want in m.
func checkValue(t *testing.T, m *bpf.Map, key uint32, want uint64) {
	t.Helper()

	value := make([]byte, 8)
	if err := m.Lookup(u32Key(key), value, 0); err != nil {
		t.Fatalf("Lookup %d: %v", key, err)
	}
	if got := binary.NativeEndian.Uint64(value); got != want {
		t.Errorf("key %d = %#x, want %#x", key, got, want)
	}
}

// TestMapElemOps loads sanitize_enum64.bpf.o through the layer and runs the
// element operations on its two-entry wide_values hash map: Update with each
// flag, Lookup, a NextKey walk, LookupAndDelete and Delete. The core errors
// carry the kernel errno for an existing key, a missing key and a full map.
// A kernel before 5.14 has no LookupAndDelete for hash maps and returns
// ENOTSUPP, and the key is then removed with Delete. It needs root and skips
// when the kernel refuses bpf() with EPERM or EACCES.
func TestMapElemOps(t *testing.T) {
	obj := loadObject(t, filepath.Join(progsDir, "sanitize_enum64.bpf.o"))
	m := obj.Map("wide_values")
	if m == nil {
		t.Fatal("no wide_values map")
	}

	if keys := mapKeys(t, m); len(keys) != 0 {
		t.Fatalf("keys of the new map = %v, want none", keys)
	}
	for _, u := range []struct {
		key   uint32
		value uint64
		flags uint64
		want  error
	}{
		{1, 0x1111, libbpf.BPF_NOEXIST, nil},
		{1, 0x2222, libbpf.BPF_NOEXIST, syscall.EEXIST},
		{2, 0x2222, libbpf.BPF_EXIST, syscall.ENOENT},
		{2, 0x2222, libbpf.BPF_ANY, nil},
		{3, 0x3333, libbpf.BPF_ANY, syscall.E2BIG},
	} {
		err := m.Update(u32Key(u.key), u64Value(u.value), u.flags)
		if u.want == nil && err != nil || u.want != nil && !errors.Is(err, u.want) {
			t.Errorf("Update %d with flags %d = %v, want %v", u.key, u.flags, err, u.want)
		}
	}
	checkValue(t, m, 1, 0x1111)
	checkValue(t, m, 2, 0x2222)
	if keys := mapKeys(t, m); !slices.Equal(keys, []uint32{1, 2}) {
		t.Errorf("keys = %v, want [1 2]", keys)
	}

	value := make([]byte, 8)
	switch err := m.LookupAndDelete(u32Key(1), value, 0); {
	case errors.Is(err, enotsupp):
		t.Logf("LookupAndDelete on a hash map: %v; deleting key 1 instead", err)
		if err := m.Delete(u32Key(1), 0); err != nil {
			t.Fatalf("Delete 1: %v", err)
		}
	case err != nil:
		t.Fatalf("LookupAndDelete 1: %v", err)
	case binary.NativeEndian.Uint64(value) != 0x1111:
		t.Errorf("LookupAndDelete 1 = %x, want 0x1111", value)
	}
	if err := m.Lookup(u32Key(1), value, 0); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("Lookup 1 after its delete = %v, want ENOENT", err)
	}

	if err := m.Delete(u32Key(2), 0); err != nil {
		t.Fatalf("Delete 2: %v", err)
	}
	if err := m.Delete(u32Key(2), 0); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("Delete 2 twice = %v, want ENOENT", err)
	}
	if keys := mapKeys(t, m); len(keys) != 0 {
		t.Errorf("keys after the deletes = %v, want none", keys)
	}
}

// TestMapSetInitialValueLoad sets a new .data initial value for
// global_data.bpf.o through the layer before Load, with other data_magic and
// data_counter values. After Load the map holds the new value, a second
// SetInitialValue is the core EBUSY, and handle_global, attached to
// do_sys_openat2, counts on from the new data_counter. It needs root and
// skips when the kernel refuses bpf() or the kprobe with EPERM or EACCES.
func TestMapSetInitialValueLoad(t *testing.T) {
	const (
		newMagic   = 0x0102030405060708
		newCounter = 5000
	)
	obj := openObject(t, globalDataObject)
	data := obj.Map(".data")
	if data == nil {
		t.Fatal("no .data map")
	}
	value := bytes.Clone(data.InitialValue())
	binary.NativeEndian.PutUint64(value[0:], newMagic)
	binary.NativeEndian.PutUint64(value[8:], newCounter)
	if err := data.SetInitialValue(value); err != nil {
		t.Fatalf("SetInitialValue: %v", err)
	}

	if err := obj.Load(); err != nil {
		skipIfNotPermitted(t, "bpf()", err)
		t.Fatalf("Load: %v", err)
	}
	loaded := make([]byte, data.ValueSize())
	if err := data.Lookup(u32Key(0), loaded, 0); err != nil {
		t.Fatalf("Lookup .data: %v", err)
	}
	if !bytes.Equal(loaded, value) {
		t.Errorf(".data after Load = %x, want %x", loaded, value)
	}
	checkCoreErrno(t, "SetInitialValue after Load", data.SetInitialValue(value), syscall.EBUSY)

	link, err := obj.Program("handle_global").AttachKprobe(false, "do_sys_openat2")
	if err != nil {
		skipIfNotPermitted(t, "kprobe attach", err)
		t.Fatalf("AttachKprobe: %v", err)
	}
	defer link.Destroy()
	triggerOpen(t)

	if err := data.Lookup(u32Key(0), loaded, 0); err != nil {
		t.Fatalf("Lookup .data after the open: %v", err)
	}
	if got := binary.NativeEndian.Uint64(loaded[0:]); got != newMagic {
		t.Errorf("data_magic = %#x, want %#x", got, uint64(newMagic))
	}
	if got := binary.NativeEndian.Uint64(loaded[8:]); got <= newCounter {
		t.Errorf("data_counter = %d, want more than %d", got, newCounter)
	}
}
