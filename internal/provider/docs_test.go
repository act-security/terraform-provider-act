package provider_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"

	"github.com/act-security/terraform-provider-act/internal/provider"
)

type docKind struct {
	label       string
	dir         string
	exampleFile string
	extraFiles  []string
}

var (
	resourceDocs   = docKind{label: "resource", dir: "resources", exampleFile: "resource.tf", extraFiles: []string{"import.sh"}}
	dataSourceDocs = docKind{label: "data source", dir: "data-sources", exampleFile: "data-source.tf"}
)

func TestEveryResourceAndDataSourceShipsDocsAndExamples(t *testing.T) {
	root := repoRoot(t)
	ctx := context.Background()
	p := provider.New("test")()

	var meta fwprovider.MetadataResponse
	p.Metadata(ctx, fwprovider.MetadataRequest{}, &meta)

	resources := make([]string, 0)
	for _, factory := range p.Resources(ctx) {
		var resp resource.MetadataResponse
		factory().Metadata(ctx, resource.MetadataRequest{ProviderTypeName: meta.TypeName}, &resp)
		resources = append(resources, resp.TypeName)
	}
	dataSources := make([]string, 0)
	for _, factory := range p.DataSources(ctx) {
		var resp datasource.MetadataResponse
		factory().Metadata(ctx, datasource.MetadataRequest{ProviderTypeName: meta.TypeName}, &resp)
		dataSources = append(dataSources, resp.TypeName)
	}

	for _, kind := range []struct {
		docKind
		typeNames []string
	}{{resourceDocs, resources}, {dataSourceDocs, dataSources}} {
		for _, typeName := range kind.typeNames {
			short := strings.TrimPrefix(typeName, meta.TypeName+"_")
			t.Run(kind.dir+"/"+typeName, func(t *testing.T) {
				example := requireContent(t, root, "examples", kind.dir, typeName, kind.exampleFile)
				requireContent(t, root, "templates", kind.dir, short+".md.tmpl")
				doc := requireContent(t, root, "docs", kind.dir, short+".md")
				requireRendered(t, doc, example, kind.exampleFile)
				for _, extra := range kind.extraFiles {
					requireRendered(t, doc, requireContent(t, root, "examples", kind.dir, typeName, extra), extra)
				}
			})
		}
		t.Run(kind.dir+"/no orphans", func(t *testing.T) {
			for _, dir := range []string{"templates", "docs"} {
				for _, name := range listNames(t, filepath.Join(root, dir, kind.dir)) {
					short := strings.TrimSuffix(strings.TrimSuffix(name, ".tmpl"), ".md")
					if !slices.Contains(kind.typeNames, meta.TypeName+"_"+short) {
						t.Errorf("%s/%s/%s has no registered %s named %s_%s", dir, kind.dir, name, kind.label, meta.TypeName, short)
					}
				}
			}
			for _, name := range listNames(t, filepath.Join(root, "examples", kind.dir)) {
				if !slices.Contains(kind.typeNames, name) {
					t.Errorf("examples/%s/%s has no registered %s named %s", kind.dir, name, kind.label, name)
				}
			}
		})
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("expected the repository root at %s: %v", root, err)
	}
	return root
}

func requireContent(t *testing.T, root string, parts ...string) string {
	t.Helper()
	rel := filepath.Join(parts...)
	content, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Errorf("%s is missing. Every resource and data source ships an example, a template and a generated doc; see CONTRIBUTING.md", rel)
		return ""
	}
	if strings.TrimSpace(string(content)) == "" {
		t.Errorf("%s is empty", rel)
	}
	return string(content)
}

func requireRendered(t *testing.T, doc, example, file string) {
	t.Helper()
	if doc == "" || strings.TrimSpace(example) == "" {
		return
	}
	if !strings.Contains(doc, strings.TrimSpace(example)) {
		t.Errorf("the generated doc does not show %s. Render it from the template and run make docs", file)
	}
}

func listNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}
