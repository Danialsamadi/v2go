package tester

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	xcore "github.com/xtls/xray-core/core"
	xserial "github.com/xtls/xray-core/infra/conf/serial"

	_ "github.com/xtls/xray-core/main/distro/all"

	"v2ray-config-aggregator/internal/converter"
)

type Result struct {
	Link    string
	DelayMs int
	// ExitIP is the address traffic actually emerges from, as reported by a
	// probe sent through the proxy. It is the only trustworthy basis for
	// geolocation: the entry host is frequently a CDN edge or a relay in a
	// different country. Empty if the probe failed.
	ExitIP string
}

// exitIPURL returns the caller's apparent address. Fetched only for configs
// that already passed the connectivity check, so it costs one extra request
// per working config rather than one per candidate.
const (
	exitIPURL     = "http://www.cloudflare.com/cdn-cgi/trace"
	exitIPTimeout = 4 * time.Second
)

// TestAll tests every link and returns a result per link, in input order.
//
// onPass, if non-nil, is called with each result the moment it passes, before
// the run finishes. It is called from many goroutines at once, so it must do
// its own locking. Its purpose is to let callers persist working configs as
// they are found, so an interrupted or crashed run still yields something.
func TestAll(ctx context.Context, links []string, testURL string, timeoutSec, concurrent int, onPass func(Result)) []Result {
	timeout := time.Duration(timeoutSec) * time.Second

	results := make([]Result, len(links))
	for i, l := range links {
		results[i] = Result{Link: l, DelayMs: -1}
	}

	sem := make(chan struct{}, concurrent)
	var wg sync.WaitGroup
	var done, working atomic.Int64
	total := int64(len(links))

	log.Printf("Testing %d config(s) with %d concurrent workers...", total, concurrent)

	for i, link := range links {
		// Stop dispatching once cancelled (Ctrl-C). Waiting for a free worker
		// must watch ctx too, or a full pool holds the loop until a slot frees.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			log.Printf("  Cancelled: stopping after %d/%d tested, %d working",
				done.Load(), total, working.Load())
			break
		}
		wg.Add(1)
		go func(idx int, l string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					results[idx].DelayMs = -1
				}
			}()

			delay, exitIP := testOne(ctx, l, testURL, timeout)
			results[idx].DelayMs = delay
			results[idx].ExitIP = exitIP

			d := done.Add(1)
			if delay > 0 {
				working.Add(1)
				if onPass != nil {
					onPass(results[idx])
				}
			}
			if d%500 == 0 || d == total {
				log.Printf("  Progress: %d/%d tested, %d working", d, total, working.Load())
			}
		}(i, link)
	}

	wg.Wait()
	return results
}

func testOne(ctx context.Context, link, testURL string, timeout time.Duration) (int, string) {
	outbound, err := converter.ConvertLink(link)
	if err != nil {
		return -1, ""
	}

	fullConfig := converter.M{
		"log": converter.M{"loglevel": "none"},
		"outbounds": []converter.M{
			outbound,
			{"protocol": "freedom", "tag": "direct"},
		},
	}

	jsonBytes, err := json.Marshal(fullConfig)
	if err != nil {
		return -1, ""
	}

	cfg, err := xserial.LoadJSONConfig(bytes.NewReader(jsonBytes))
	if err != nil {
		return -1, ""
	}

	instance, err := xcore.New(cfg)
	if err != nil {
		return -1, ""
	}
	if err := instance.Start(); err != nil {
		return -1, ""
	}
	defer instance.Close()

	dialer := func(dialCtx context.Context, network, addr string) (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		port, err := net.LookupPort(network, portStr)
		if err != nil {
			return nil, err
		}
		dest := xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(port))
		return xcore.Dial(dialCtx, instance, dest)
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext:       dialer,
			DisableKeepAlives: true,
		},
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Derived from ctx so a cancel aborts tests in flight instead of letting
	// each run out its full timeout. Results already verified are kept; an
	// aborted test had verified nothing.
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "GET", testURL, nil)
	if err != nil {
		return -1, ""
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return -1, ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		return int(time.Since(start).Milliseconds()), fetchExitIP(ctx, client)
	}
	return -1, ""
}

// fetchExitIP asks, through the already-running proxy, which address the
// traffic appears to come from. The response is attacker-controlled — the
// proxy operator can return anything — so it is size-limited and the result
// must parse as an IP before it is used.
func fetchExitIP(ctx context.Context, client *http.Client) string {
	ctx, cancel := context.WithTimeout(ctx, exitIPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", exitIPURL, nil)
	if err != nil {
		return ""
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(body), "\n") {
		if v, ok := strings.CutPrefix(line, "ip="); ok {
			if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil {
				return ip.String()
			}
			return ""
		}
	}
	return ""
}
