// Command contract generates or checks the qualified host-protocol Go bindings.
// Run from api/tools. Network access is disabled for generator subprocesses.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const generatorModule = "github.com/oapi-codegen/oapi-codegen/v2"
const generatorVersion = "v2.8.1"
const sourceRepository = "Neticora/neticora-docker-runnerd"
const consumerRepository = "Neticora/neticora-alpha"

type generationLock struct {
	FormatVersion    int               `json:"formatVersion"`
	ProtocolVersion  string            `json:"protocolVersion"`
	GoVersion        string            `json:"goVersion"`
	GeneratorModule  string            `json:"generatorModule"`
	GeneratorVersion string            `json:"generatorVersion"`
	Provenance       map[string]string `json:"provenance"`
	Inputs           map[string]string `json:"inputs"`
	Outputs          map[string]string `json:"outputs"`
}

func digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func read(name string) []byte {
	b, err := os.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return b
}

func fail(message string) { panic(message) }

func applyHostEventUnionFieldCleanup(generated []byte) []byte {
	observationOld := "if t.Observation != nil {\n\t\tobject[\"observation\"], err = json.Marshal(t.Observation)\n\t\tif err != nil {\n\t\t\treturn nil, fmt.Errorf(\"error marshaling 'observation': %w\", err)\n\t\t}\n\t}\n"
	observationNew := "if t.Observation != nil {\n\t\tobject[\"observation\"], err = json.Marshal(t.Observation)\n\t\tif err != nil {\n\t\t\treturn nil, fmt.Errorf(\"error marshaling 'observation': %w\", err)\n\t\t}\n\t} else {\n\t\tdelete(object, \"observation\")\n\t}\n"
	providerOld := "if t.ProviderObservation != nil {\n\t\tobject[\"providerObservation\"], err = json.Marshal(t.ProviderObservation)\n\t\tif err != nil {\n\t\t\treturn nil, fmt.Errorf(\"error marshaling 'providerObservation': %w\", err)\n\t\t}\n\t}\n"
	providerNew := "if t.ProviderObservation != nil {\n\t\tobject[\"providerObservation\"], err = json.Marshal(t.ProviderObservation)\n\t\tif err != nil {\n\t\t\treturn nil, fmt.Errorf(\"error marshaling 'providerObservation': %w\", err)\n\t\t}\n\t} else {\n\t\tdelete(object, \"providerObservation\")\n\t}\n"
	text := string(generated)
	observationMatches := strings.Count(text, observationOld)
	providerMatches := strings.Count(text, providerOld)
	if observationMatches != 1 {
		fail(fmt.Sprintf("expected exactly one HostEvent observation marshal block, found %d", observationMatches))
	}
	if providerMatches != 1 {
		fail(fmt.Sprintf("expected exactly one HostEvent providerObservation marshal block, found %d", providerMatches))
	}
	updated := strings.Replace(text, observationOld, observationNew, 1)
	updated = strings.Replace(updated, providerOld, providerNew, 1)
	return []byte(updated)
}

func run() {
	write := flag.Bool("write", false, "regenerate output using the reviewed lock")
	update := flag.Bool("update-lock", false, "explicitly regenerate output and refresh the review lock")
	flag.Parse()
	if flag.NArg() != 0 {
		fail("unexpected arguments")
	}
	if *write && *update {
		fail("choose --write or --update-lock")
	}
	// Paths are relative to api/, including in the committed identity lock.
	api := ".."
	schemaRaw := read(filepath.Join(api, "host-protocol.v1.yaml"))
	var document struct {
		OpenAPI string `json:"openapi"`
		Dialect string `json:"jsonSchemaDialect"`
		Info    struct {
			Version string `json:"version"`
		} `json:"info"`
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(schemaRaw, &document); err != nil {
		panic(err)
	}
	if document.OpenAPI != "3.1.0" || document.Dialect != "https://json-schema.org/draft/2020-12/schema" {
		fail("unqualified OpenAPI dialect")
	}
	// Refuse external schema/template loading before invoking the generator.
	var walk func(any)
	walk = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			for _, keyword := range []string{"$dynamicRef", "$id", "$schema"} {
				if _, exists := v[keyword]; exists {
					fail("unqualified nested schema keyword: " + keyword)
				}
			}
			if ref, ok := v["$ref"]; ok {
				s, ok := ref.(string)
				if !ok || !strings.HasPrefix(s, "#/") {
					fail("remote schema reference prohibited")
				}
			}
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	var untrusted any
	if err := json.Unmarshal(schemaRaw, &untrusted); err != nil {
		panic(err)
	}
	walk(untrusted)
	lock := generationLock{
		FormatVersion:    1,
		ProtocolVersion:  document.Info.Version,
		GoVersion:        runtime.Version(),
		GeneratorModule:  generatorModule,
		GeneratorVersion: generatorVersion,
		Provenance: map[string]string{
			"sourceRepository":   sourceRepository,
			"consumerRepository": consumerRepository,
		},
		Inputs:  map[string]string{},
		Outputs: map[string]string{},
	}
	inputs := []string{"host-protocol.v1.yaml", "fixtures/manifest.json", "go-codegen.yaml", "go-codegen-overlay.yaml", "tools/go.mod", "tools/go.sum", "tools/cmd/contract/main.go"}
	var manifest struct {
		FormatVersion   int    `json:"formatVersion"`
		ProtocolVersion string `json:"protocolVersion"`
		Files           []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	if err := json.Unmarshal(read(filepath.Join(api, "fixtures/manifest.json")), &manifest); err != nil {
		panic(err)
	}
	if manifest.FormatVersion != 1 || manifest.ProtocolVersion != document.Info.Version || len(manifest.Files) == 0 {
		fail("fixture manifest/version mismatch")
	}
	seen := map[string]bool{}
	last := ""
	for _, item := range manifest.Files {
		if item.Path <= last || strings.ContainsAny(item.Path, "/\\") || item.Path == "manifest.json" {
			fail("invalid fixture manifest")
		}
		last = item.Path
		if digest(read(filepath.Join(api, "fixtures", item.Path))) != item.SHA256 {
			fail("fixture checksum mismatch: " + item.Path)
		}
		seen[item.Path] = true
		inputs = append(inputs, "fixtures/"+item.Path)
	}
	entries, err := os.ReadDir(filepath.Join(api, "fixtures"))
	if err != nil {
		panic(err)
	}
	for _, entry := range entries {
		if entry.Name() != "manifest.json" && !seen[entry.Name()] {
			fail("unlisted fixture: " + entry.Name())
		}
	}
	for _, name := range inputs {
		lock.Inputs[name] = digest(read(filepath.Join(api, name)))
	}
	lockPath := filepath.Join(api, "go-generation.lock.json")
	if !*update {
		var reviewed generationLock
		if err := json.Unmarshal(read(lockPath), &reviewed); err != nil {
			panic(err)
		}
		expected := reviewed
		expected.Outputs = map[string]string{}
		a, _ := json.Marshal(expected)
		b, _ := json.Marshal(lock)
		if !bytes.Equal(a, b) {
			fail("Go generation inputs/toolchain drifted; review and explicitly use --update-lock")
		}
	}
	goCommand := os.Getenv("GO")
	if goCommand == "" {
		goCommand = "go"
	}
	versionCommand := exec.Command(goCommand, "list", "-m", "-json", generatorModule)
	versionCommand.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOFLAGS=-mod=readonly")
	moduleBytes, err := versionCommand.Output()
	if err != nil {
		fail("cannot verify pinned generator module")
	}
	var module struct {
		Version string
		Replace any
	}
	if err := json.Unmarshal(moduleBytes, &module); err != nil {
		panic(err)
	}
	if module.Version != generatorVersion || module.Replace != nil {
		fail("generator module/version or replacement is not qualified")
	}
	cmd := exec.Command(goCommand, "tool", "oapi-codegen", "--config", "../go-codegen.yaml", "../host-protocol.v1.yaml")
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOFLAGS=-mod=readonly")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	generated, err := cmd.Output()
	if err != nil {
		fail(fmt.Sprintf("generator failed: %v\n%s", err, stderr.String()))
	}
	generated = applyHostEventUnionFieldCleanup(generated)
	// Typed decoding always validates original bytes before encoding/json binds.
	// Casts/UnmarshalJSON alone are not the host protocol validation boundary.
	names := make([]string, 0, len(document.Components.Schemas))
	for name := range document.Components.Schemas {
		names = append(names, name)
	}
	sort.Strings(names)
	var decoders strings.Builder
	decoders.WriteString("// Code generated by api/tools/cmd/contract; DO NOT EDIT.\npackage protocol\n")
	for _, name := range names {
		fmt.Fprintf(&decoders, "\n// Decode%s validates the original wire bytes before binding the generated model.\nfunc Decode%s(data []byte) (%s, error) { var value %s; err := decode(%q, data, &value); return value, err }\n", name, name, name, name, name)
	}
	decoders.WriteString("\nvar wireDecoders = map[string]func([]byte) (any, error){\n")
	for _, name := range names {
		fmt.Fprintf(&decoders, "%q: func(data []byte) (any, error) { return Decode%s(data) },\n", name, name)
	}
	decoders.WriteString("}\n")
	decoderBytes, err := format.Source([]byte(decoders.String()))
	if err != nil {
		panic(err)
	}
	artifacts := map[string][]byte{"protocol/models.gen.go": generated, "protocol/decode.gen.go": decoderBytes, "protocol/schema.gen.json": schemaRaw}
	for name, value := range artifacts {
		lock.Outputs[name] = digest(value)
	}
	if *update || *write {
		for name, value := range artifacts {
			if err := os.WriteFile(filepath.Join(api, name), value, 0644); err != nil {
				panic(err)
			}
		}
		if *update {
			b, err := json.MarshalIndent(lock, "", "  ")
			if err != nil {
				panic(err)
			}
			if err := os.WriteFile(lockPath, append(b, '\n'), 0644); err != nil {
				panic(err)
			}
		}
	} else {
		var reviewed generationLock
		if err := json.Unmarshal(read(lockPath), &reviewed); err != nil {
			panic(err)
		}
		for name, value := range artifacts {
			if digest(value) != reviewed.Outputs[name] || !bytes.Equal(value, read(filepath.Join(api, name))) {
				fail("generated Go artifact drifted: " + name)
			}
		}
		if len(reviewed.Outputs) != len(artifacts) {
			fail("unexpected generated artifacts in lock")
		}
	}
	fmt.Printf("Go generation verified: protocol=%s schema=%s generator=%s@%s toolchain=%s\n", document.Info.Version, digest(schemaRaw), generatorModule, generatorVersion, runtime.Version())
}

func main() {
	defer func() {
		if err := recover(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}()
	run()
}
