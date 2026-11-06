package dockerengine

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/moby/moby/client"
)

func TestMutationTransportRejectsReplacementAfterFinalContinuityCheck(t *testing.T) {
	for _, operation := range []string{"create", "start", "stop", "remove"} {
		t.Run(operation, func(t *testing.T) {
			var reached atomic.Int32
			isMutation := func(method, path string) bool {
				switch operation {
				case "create":
					return method == "POST" && strings.HasSuffix(path, "/containers/create")
				case "start", "stop":
					return method == "POST" && strings.HasSuffix(path, "/"+operation)
				default:
					return method == "DELETE"
				}
			}
			e, p, exists, running, creates, _ := fakeEngineWithHook(t, func(path string) {
				if path == "/containers/create" || strings.HasSuffix(path, "/start") || strings.HasSuffix(path, "/stop") || path == "/containers/owned" {
					reached.Add(1)
				}
			})
			*exists, *running = operation != "create", operation == "stop"
			var peer atomic.Value
			peer.Store("qualified-direct-dockerd-peer")
			e.connectionPeer = func(net.Conn) (string, error) { return peer.Load().(string), nil }
			var injected atomic.Bool
			api, err := client.New(client.WithHost("unix://"+e.socket), client.WithDialContext(e.dialContext), client.WithAPIVersion("1.52"), client.WithHTTPRequestHook(func(req *http.Request) error {
				if isMutation(req.Method, req.URL.Path) {
					// All preflight reads already passed. A replacement peer is
					// observed only on the actual newly opened mutation connection.
					injected.Store(true)
					peer.Store("replacement-dockerd-peer")
					_ = e.api.Close() // Force a new connection instead of old keepalive.
				}
				return nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			_ = e.api.Close()
			e.api = api
			claims, authorizations := 0, 0
			switch operation {
			case "create":
				_, err = e.Ensure(context.Background(), p, func() error { claims++; return nil })
			case "start":
				_, err = e.Start(context.Background(), p.Name, p, func() error { authorizations++; return nil })
			case "stop":
				err = e.Stop(context.Background(), p.Name, p)
			case "remove":
				err = e.Remove(context.Background(), p.Name, p)
			}
			if !errors.Is(err, ErrUnavailable) || !injected.Load() || reached.Load() != 0 || *creates != 0 {
				t.Fatalf("replacement received mutation: err=%v injected=%v requests=%d creates=%d", err, injected.Load(), reached.Load(), *creates)
			}
			if operation == "create" && claims != 1 || operation == "start" && (authorizations != 1 || *running) {
				t.Fatal("did not exercise post-claim/authorization mutation boundary")
			}
		})
	}
}

func TestReplacementDuringInspectionCannotProveAbsenceOrAdoption(t *testing.T) {
	for _, exists := range []bool{false, true} {
		t.Run(map[bool]string{false: "absence", true: "adoption"}[exists], func(t *testing.T) {
			var daemon *string
			e, p, present, _, _, current := fakeEngineWithHook(t, func(path string) {
				if strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/json") {
					*daemon = "replacement-engine"
				}
			})
			daemon = current
			*present = exists
			if _, err := e.Inspect(context.Background(), p.Name, p); !errors.Is(err, ErrUnavailable) {
				t.Fatal("replacement response trusted", err)
			}
			// Even another goroutine observing the new identity cannot make old
			// operations trust absence or mutate the replacement.
			if _, err := e.Probe(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := e.Inspect(context.Background(), p.Name, p); !errors.Is(err, ErrUnavailable) {
				t.Fatal("replacement rebound old engine", err)
			}
		})
	}
}

func TestReplacementDuringInventoryInvalidatesCompleteSnapshot(t *testing.T) {
	var daemon *string
	e, _, _, _, _, current := fakeEngineWithHook(t, func(path string) {
		if path == "/containers/json" {
			*daemon = "replacement-engine"
		}
	})
	daemon = current
	if _, err := e.Inventory(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("mixed-endpoint inventory accepted", err)
	}
}

func TestContinuityRecheckedAfterCreationClaimAndAuthorization(t *testing.T) {
	t.Run("creation-claim", func(t *testing.T) {
		e, p, _, _, creates, daemon := fakeEngine(t)
		_, err := e.Ensure(context.Background(), p, func() error { *daemon = "replacement"; return nil })
		if !errors.Is(err, ErrUnavailable) || *creates != 0 {
			t.Fatal("created on changed engine", err)
		}
	})
	t.Run("authorization", func(t *testing.T) {
		e, p, exists, running, _, daemon := fakeEngine(t)
		*exists = true
		_, err := e.Start(context.Background(), p.Name, p, func() error { *daemon = "replacement"; return nil })
		if !errors.Is(err, ErrUnavailable) || *running {
			t.Fatal("started on changed engine", err)
		}
	})
}

func TestHeadroomDoesNotInventFreeStorageOrQuarantineReads(t *testing.T) {
	e, p, _, _, _, _ := fakeEngine(t)
	if err := e.CheckHeadroom(context.Background(), ^uint64(0)); !errors.Is(err, ErrStoragePressure) {
		t.Fatal("unavailable capacity admitted", err)
	}
	if err := e.CheckHeadroom(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Inspect(context.Background(), p.Name, p); !errors.Is(err, ErrAbsent) {
		t.Fatal("headroom pressure blocked verified absence", err)
	}
}
