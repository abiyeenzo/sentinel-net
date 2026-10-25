package scanner

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/abiyeenzo/sentinel-net/internal/netscope"
)

func hangingDialer(started chan<- struct{}) DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if started != nil {
			select {
			case started <- struct{}{}:
			default:
			}
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
}

func TestDetectOpenLoopbackListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	res, err := ScanTCP(context.Background(), TCPOptions{
		Target:  "127.0.0.1",
		Ports:   []int{port},
		Timeout: 800 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("ScanTCP failed: %v", err)
	}
	if len(res) != 1 || res[0].State != "open" || res[0].Reason != "tcp-connect" {
		t.Fatalf("expected open tcp-connect observation, got %+v", res)
	}
}

func TestDetectClosedPortRST(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	closedPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	res, err := ScanTCP(context.Background(), TCPOptions{
		Target:  "127.0.0.1",
		Ports:   []int{closedPort},
		Timeout: 800 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("ScanTCP failed: %v", err)
	}
	if len(res) != 1 || res[0].State != "closed" || res[0].Reason != "ECONNREFUSED" {
		t.Fatalf("expected closed ECONNREFUSED observation, got %+v", res)
	}
}

func TestTimeoutClassifiedAsUnknownWithRetries(t *testing.T) {
	res, err := ScanTCP(context.Background(), TCPOptions{
		Target:  "127.0.0.1",
		Ports:   []int{443},
		Timeout: 120 * time.Millisecond,
		Retries: 1,
		Dial:    hangingDialer(nil),
	})
	if err != nil {
		t.Fatalf("ScanTCP failed: %v", err)
	}
	if res[0].State != "unknown" || res[0].Reason != "timeout" || res[0].Attempts != 2 {
		t.Fatalf("expected unknown/timeout with 2 attempts, got %+v", res[0])
	}
}

func TestRefusesUnsafeBoundsAndPreCancelledContext(t *testing.T) {
	if _, err := ScanTCP(context.Background(), TCPOptions{
		Target:      "127.0.0.1",
		Ports:       []int{80},
		Concurrency: 500,
	}); err == nil {
		t.Fatal("expected excessive concurrency to be rejected")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ScanTCP(ctx, TCPOptions{
		Target: "127.0.0.1",
		Ports:  []int{80},
	})
	if !errors.Is(err, ErrCancelled) {
		t.Fatalf("expected ErrCancelled, got %v", err)
	}
}

func TestCancelsActiveProbesPromptly(t *testing.T) {
	started := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-started
		time.Sleep(25 * time.Millisecond)
		cancel()
	}()

	t0 := time.Now()
	_, err := ScanTCP(ctx, TCPOptions{
		Target:      "127.0.0.1",
		Ports:       []int{80, 443, 8080, 8443},
		Timeout:     5 * time.Second,
		Concurrency: 2,
		Dial:        hangingDialer(started),
	})
	elapsed := time.Since(t0)

	if !errors.Is(err, ErrCancelled) {
		t.Fatalf("expected ErrCancelled when aborting in-flight probes, got %v", err)
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("cancellation took too long: %s", elapsed)
	}
}

func TestCancelsActiveBannerReadPromptly(t *testing.T) {
	accepted := make(chan net.Conn, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case accepted <- c:
			default:
				_ = c.Close()
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		// Wait until ScanTCP establishes TCP and enters GrabBanner's blocking Read.
		var held []net.Conn
		defer func() {
			for _, c := range held {
				_ = c.Close()
			}
		}()
		c := <-accepted
		held = append(held, c)
		time.Sleep(35 * time.Millisecond)
		cancel()
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	t0 := time.Now()
	_, err = ScanTCP(ctx, TCPOptions{
		Target:  "127.0.0.1",
		Ports:   []int{port},
		Timeout: 4 * time.Second,
		Banner:  true,
	})
	elapsed := time.Since(t0)

	if !errors.Is(err, ErrCancelled) {
		t.Fatalf("expected ErrCancelled on live banner socket read, got %v", err)
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("banner cancellation took too long: %s", elapsed)
	}
}

func TestScanNetworkAggregatesPosture(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	rep, err := ScanNetwork(context.Background(), NetworkOptions{
		Targets: []netscope.TargetHost{{IP: "127.0.0.1", Scope: "loopback"}},
		Ports:   []int{port},
		Timeout: 800 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("ScanNetwork failed: %v", err)
	}
	if rep.Summary.OpenPorts != 1 || rep.Target != "127.0.0.1" {
		t.Fatalf("unexpected ScanNetwork report: %+v", rep.Summary)
	}
}
