package provider_test

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	releaseManifestFile = ".release-please-manifest.json"
	releaseManifestKey  = "."
	providerExampleFile = "examples/provider/provider.tf"
)

var (
	pinnedVersionPattern = regexp.MustCompile(`version\s*=\s*"~>\s*(\d+\.\d+)(?:\.\d+)?"`)
	pinnedVersionSources = []string{"README.md", "examples", "templates", "docs"}
	pinnedVersionExts    = []string{".md", ".tf", ".tmpl"}
)

func TestPinnedVersionsMatchTheCurrentRelease(t *testing.T) {
	root := repoRoot(t)
	want := releasedMinor(t, root)

	requirePinIn(t, root, providerExampleFile)
	for _, pin := range collectPins(t, root) {
		if pin.minor != want {
			t.Errorf(`%s pins version = "~> %s"; the current release is %s.x, so pin "~> %s" and run make docs`, pin.file, pin.minor, want, want)
		}
	}
}

type versionPin struct {
	file  string
	minor string
}

func releasedMinor(t *testing.T, root string) string {
	t.Helper()
	content := requireContent(t, root, releaseManifestFile)
	var manifest map[string]string
	if err := json.Unmarshal([]byte(content), &manifest); err != nil {
		t.Fatalf("parse %s: %v", releaseManifestFile, err)
	}
	version, ok := manifest[releaseManifestKey]
	if !ok {
		t.Fatalf("%s has no %q entry", releaseManifestFile, releaseManifestKey)
	}
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		t.Fatalf("%s holds %q, not a semantic version", releaseManifestFile, version)
	}
	return parts[0] + "." + parts[1]
}

func requirePinIn(t *testing.T, root, rel string) {
	t.Helper()
	content := requireContent(t, root, rel)
	if !pinnedVersionPattern.MatchString(content) {
		t.Errorf(`%s must pin the provider with version = "~> MAJOR.MINOR"`, rel)
	}
}

func collectPins(t *testing.T, root string) []versionPin {
	t.Helper()
	var pins []versionPin
	for _, source := range pinnedVersionSources {
		err := filepath.WalkDir(filepath.Join(root, source), func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() || !hasPinnedVersionExt(path) {
				return err
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			for _, match := range pinnedVersionPattern.FindAllStringSubmatch(string(content), -1) {
				pins = append(pins, versionPin{file: rel, minor: match[1]})
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scan %s for pinned versions: %v", source, err)
		}
	}
	return pins
}

func hasPinnedVersionExt(path string) bool {
	ext := filepath.Ext(path)
	for _, allowed := range pinnedVersionExts {
		if ext == allowed {
			return true
		}
	}
	return false
}
