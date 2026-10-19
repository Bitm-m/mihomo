//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"errors"
	"testing"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestSelfBypassSocketAddressReleaseIntegration(t *testing.T) {
	requireEBPFIntegration(t, "combine socket-address marking with release cleanup")
	requireOwnerMarkingHelper(t, CiliumEBPF.CGroupSockAddr)
	owner := integrationSelfBypassOwner(t)
	root, err := DetectCgroup2Root()
	if err != nil {
		t.Fatal(err)
	}
	path, dedicated := createIntegrationCgroup(t, root, 171)
	if !dedicated {
		t.Skip("cannot create a dedicated cgroup")
	}
	moveCurrentProcessToCgroup(t, path, root)
	b, err := NewSelfBypassWithCapacity(8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	})
	if err = b.attachCgroupSocketAddr(path, SelfBypassCgroupConfig{EnableUDP: true}, owner); err != nil {
		t.Fatal(err)
	}
	if err = b.attachCgroupRelease(path); err != nil {
		t.Fatal(err)
	}
	if len(b.links) != 2 || len(b.programs) != 2 {
		t.Fatal("adding release cleanup lost ownership of the marking hooks")
	}
	for iteration := 0; iteration < 16; iteration++ {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
		if err != nil {
			unix.Close(fd)
			t.Fatal(err)
		}
		err = unix.Sendto(fd, []byte{1}, 0, &unix.SockaddrInet4{Port: 9, Addr: [4]byte{127, 0, 0, 1}})
		if err != nil {
			unix.Close(fd)
			t.Fatal(err)
		}
		var metadata uint32
		lookupErr := b.sockets.Lookup(cookie, &metadata)
		if err = unix.Close(fd); err != nil {
			t.Fatal(err)
		}
		if lookupErr != nil || metadata&SocketMetadataSelfBypass == 0 {
			t.Fatalf("socket-address hook did not mark socket: metadata=%d error=%v", metadata, lookupErr)
		}
		deadline := time.Now().Add(time.Second)
		for {
			err = b.sockets.Lookup(cookie, &metadata)
			if errors.Is(err, CiliumEBPF.ErrKeyNotExist) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("closed socket retained: %v", err)
			}
			time.Sleep(time.Millisecond)
		}
	}
}
