package provider

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	supportManifestPath = "../../api/support.json"
	contractPath        = "../../api/openapi.json"
	updateSupportEnv    = "UPDATE_SUPPORT"
	clientCallSuffix    = "WithResponse"
	bodyCallSuffix      = "WithBody"
)

var clientCallDirs = []string{".", "../client"}

var acknowledgedItems = []string{}

type supportManifest struct {
	Items        []string `json:"items"`
	Acknowledged []string `json:"acknowledged"`
}

func TestSupportManifest(t *testing.T) {
	want := renderSupportManifest(t, supportManifest{Items: supportedItems(t), Acknowledged: acknowledgedItems})
	if os.Getenv(updateSupportEnv) == "1" {
		writeSupportManifest(t, want)
		return
	}
	got, err := os.ReadFile(supportManifestPath)
	if err != nil {
		t.Fatalf("read api/support.json: %v. Run: make support", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("api/support.json is stale. Run: make support\nwant:\n%s", want)
	}
}

func supportedItems(t *testing.T) []string {
	t.Helper()
	items := slices.Concat(integrationItems(t), notificationActionItems(), operationItems(t))
	slices.Sort(items)
	return slices.Compact(items)
}

func integrationItems(t *testing.T) []string {
	t.Helper()
	var items []string
	for _, newResource := range New("test")().Resources(t.Context()) {
		integration, ok := newResource().(*integrationResource)
		if !ok {
			continue
		}
		items = append(items, itemsOfIntegrationKind(integration.kind)...)
	}
	return items
}

func itemsOfIntegrationKind(kind integrationKind) []string {
	integrationType := string(kind.apiType)
	items := []string{"integration-type:" + integrationType, integrationFieldItem(integrationType, kind.secret.wire)}
	for _, field := range kind.config {
		items = append(items, integrationFieldItem(integrationType, field.wire))
	}
	return items
}

func integrationFieldItem(integrationType, wire string) string {
	return "integration-field:" + integrationType + "." + wire
}

func notificationActionItems() []string {
	var items []string
	for action := range maps.Keys(actionBlocks()) {
		items = append(items, "notification-action:"+action)
	}
	return items
}

func operationItems(t *testing.T) []string {
	t.Helper()
	operationIDs := contractOperationIDs(t)
	var items []string
	for _, call := range clientCalls(t) {
		operationID, ok := operationIDs[strings.ToLower(call)]
		if !ok {
			t.Fatalf("the provider calls %s%s, which is no operation in api/openapi.json", call, clientCallSuffix)
		}
		items = append(items, "operation:"+operationID)
	}
	return items
}

func contractOperationIDs(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatalf("read api/openapi.json: %v", err)
	}
	var contract struct {
		Paths map[string]map[string]struct {
			OperationID string `json:"operationId"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(raw, &contract); err != nil {
		t.Fatalf("parse api/openapi.json: %v", err)
	}
	operationIDs := map[string]string{}
	for _, operations := range contract.Paths {
		for _, operation := range operations {
			operationIDs[strings.ToLower(operation.OperationID)] = operation.OperationID
		}
	}
	return operationIDs
}

func clientCalls(t *testing.T) []string {
	t.Helper()
	var calls []string
	for _, dir := range clientCallDirs {
		for _, file := range sourceFilesIn(t, dir) {
			calls = append(calls, clientCallsIn(t, file)...)
		}
	}
	return calls
}

func sourceFilesIn(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("list %s: %v", dir, err)
	}
	return slices.DeleteFunc(files, func(file string) bool { return strings.HasSuffix(file, "_test.go") })
}

func clientCallsIn(t *testing.T, file string) []string {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	var calls []string
	ast.Inspect(parsed, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if ok && strings.HasSuffix(selector.Sel.Name, clientCallSuffix) {
			call := strings.TrimSuffix(selector.Sel.Name, clientCallSuffix)
			calls = append(calls, strings.TrimSuffix(call, bodyCallSuffix))
		}
		return true
	})
	return calls
}

func renderSupportManifest(t *testing.T, manifest supportManifest) []byte {
	t.Helper()
	rendered, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("render api/support.json: %v", err)
	}
	return append(rendered, '\n')
}

func writeSupportManifest(t *testing.T, manifest []byte) {
	t.Helper()
	if err := os.WriteFile(supportManifestPath, manifest, 0o600); err != nil {
		t.Fatalf("write api/support.json: %v", err)
	}
}
