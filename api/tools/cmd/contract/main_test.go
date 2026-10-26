package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const observationMarshalBlock = "if t.Observation != nil {\n\t\tobject[\"observation\"], err = json.Marshal(t.Observation)\n\t\tif err != nil {\n\t\t\treturn nil, fmt.Errorf(\"error marshaling 'observation': %w\", err)\n\t\t}\n\t}\n"
const providerMarshalBlock = "if t.ProviderObservation != nil {\n\t\tobject[\"providerObservation\"], err = json.Marshal(t.ProviderObservation)\n\t\tif err != nil {\n\t\t\treturn nil, fmt.Errorf(\"error marshaling 'providerObservation': %w\", err)\n\t\t}\n\t}\n"

func panicMessage(fn func()) (string, bool) {
	panicked := false
	message := ""
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				panicked = true
				message = fmt.Sprint(recovered)
			}
		}()
		fn()
	}()
	return message, panicked
}

func TestApplyHostEventUnionFieldCleanupRequiresExactPatternCount(t *testing.T) {
	fixture := []byte("func (t HostEvent) MarshalJSON() ([]byte, error) {\n\tvar err error\n\tobject := make(map[string]json.RawMessage)\n" + observationMarshalBlock + providerMarshalBlock + "\treturn json.Marshal(object)\n}\n")

	outputMessage, panicked := panicMessage(func() { _ = applyHostEventUnionFieldCleanup(fixture) })
	if panicked {
		t.Fatalf("expected cleanup to succeed for pre-transform source, got %q", outputMessage)
	}

	transformed := applyHostEventUnionFieldCleanup(fixture)
	if strings.Count(string(transformed), `delete(object, "observation")`) != 1 {
		t.Fatal("observation cleanup branch missing after transformation")
	}
	if strings.Count(string(transformed), `delete(object, "providerObservation")`) != 1 {
		t.Fatal("providerObservation cleanup branch missing after transformation")
	}

	missingObservation := []byte(strings.Replace(string(fixture), observationMarshalBlock, "", 1))
	message, panicked := panicMessage(func() { _ = applyHostEventUnionFieldCleanup(missingObservation) })
	if !panicked || !strings.Contains(message, "observation marshal block") {
		t.Fatalf("expected observation-pattern failure, got panic=%v message=%q", panicked, message)
	}

	duplicateProvider := []byte(strings.Replace(string(fixture), providerMarshalBlock, providerMarshalBlock+providerMarshalBlock, 1))
	message, panicked = panicMessage(func() { _ = applyHostEventUnionFieldCleanup(duplicateProvider) })
	if !panicked || !strings.Contains(message, "providerObservation marshal block") {
		t.Fatalf("expected provider-pattern failure, got panic=%v message=%q", panicked, message)
	}
}

// Exercise the real CLI against isolated contract trees, never the checkout.
func TestGenerationAndDriftFailures(t *testing.T) {
	goCommand := os.Getenv("GO")
	if goCommand == "" {
		goCommand = "go"
	}
	binary := filepath.Join(t.TempDir(), "contract")
	build := exec.Command(goCommand, "build", "-mod=readonly", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	api, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	var lock generationLock
	if err := json.Unmarshal(read(filepath.Join(api, "go-generation.lock.json")), &lock); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, file, expected string
		modify               func([]byte) []byte
	}{
		{"unchanged", "", "", nil},
		{"generated model", "protocol/models.gen.go", "artifact drifted", func(b []byte) []byte { return append(b, []byte("\n// manual edit\n")...) }},
		{"schema", "host-protocol.v1.yaml", "inputs/toolchain drifted", func(b []byte) []byte { return append(b, '\n') }},
		{"fixture", "fixtures/validation.json", "fixture checksum mismatch", func(b []byte) []byte { return append(b, '\n') }},
		{"configuration", "go-codegen.yaml", "inputs/toolchain drifted", func(b []byte) []byte { return append(b, '\n') }},
		{"generator dependency", "tools/go.mod", "inputs/toolchain drifted", func(b []byte) []byte { return append(b, []byte("\n// unreviewed\n")...) }},
		{"external reference", "host-protocol.v1.yaml", "remote schema reference prohibited", func(b []byte) []byte {
			return bytes.Replace(b, []byte("#/components/schemas/UInt64String"), []byte("https://invalid.example/schema"), 1)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stage := t.TempDir()
			paths := []string{"go-generation.lock.json"}
			for name := range lock.Inputs {
				paths = append(paths, name)
			}
			for name := range lock.Outputs {
				paths = append(paths, name)
			}
			for _, name := range paths {
				destination := filepath.Join(stage, name)
				if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(destination, read(filepath.Join(api, name)), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if tc.modify != nil {
				file := filepath.Join(stage, tc.file)
				if err := os.WriteFile(file, tc.modify(read(file)), 0644); err != nil {
					t.Fatal(err)
				}
			}
			command := exec.Command(binary)
			command.Dir = filepath.Join(stage, "tools")
			command.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local")
			output, err := command.CombinedOutput()
			if tc.expected == "" {
				if err != nil {
					t.Fatalf("clean check: %v\n%s", err, output)
				}
			} else if err == nil || !strings.Contains(string(output), tc.expected) {
				t.Fatalf("wanted failure %q: %v\n%s", tc.expected, err, output)
			}
			if !bytes.Equal(read(filepath.Join(stage, "go-generation.lock.json")), read(filepath.Join(api, "go-generation.lock.json"))) {
				t.Fatal("check mutated the lock")
			}
		})
	}
}
