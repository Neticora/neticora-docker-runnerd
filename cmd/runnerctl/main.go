package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	socket := flag.String("socket", "/run/neticora-runnerd/control.sock", "local control socket")
	afterID := flag.String("after-execution", "", "exclusive execution diagnostic cursor")
	afterGeneration := flag.String("after-generation", "", "execution diagnostic generation cursor")
	executionID := flag.String("execution", "", "exact execution ID for trusted Kata evidence")
	generation := flag.String("generation", "", "exact generation for trusted Kata evidence")
	flag.Parse()
	if flag.NArg() != 1 {
		return errors.New("usage: runnerctl [--socket PATH] [--execution ID --generation N] status|doctor|capabilities|executions|kata-evidence|drain")
	}
	command := flag.Arg(0)
	method := http.MethodGet
	switch command {
	case "status", "doctor", "capabilities", "executions":
	case "kata-evidence":
		if *executionID == "" || *generation == "" {
			return errors.New("exact execution and generation required")
		}
	case "drain":
		method = http.MethodPost
	default:
		return errors.New("unsupported administrative command")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", *socket)
	}, DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	query := url.Values{}
	if command == "executions" {
		query.Set("afterExecutionId", *afterID)
		query.Set("afterGeneration", *afterGeneration)
	}
	if command == "kata-evidence" {
		query.Set("executionId", *executionID)
		query.Set("generation", *generation)
	}
	req, _ := http.NewRequest(method, "http://localhost/"+command+"?"+query.Encode(), nil)
	response, err := client.Do(req)
	if err != nil {
		return errors.New("local service unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("local command rejected")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(data) > 65536 {
		return errors.New("invalid local response")
	}
	_, err = fmt.Fprintln(os.Stdout, strings.TrimSpace(string(data)))
	return err
}
