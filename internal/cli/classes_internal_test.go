// `derive classes` through the verb: the line it prints, and every
// refusal by name with its exit code. The vocabulary is a stranger's:
// classes this org does not have, declared in its own policy.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func classesPolicy(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "assert-policy.json")
	doc := `{
	  "schema": 9,
	  "evidence": {
	    "sbomSuffix": ".spdx.json", "checksums": "SHA256SUMS",
	    "umbrellaBundle": "attestations.intoto.jsonl", "manifestAsset": "evidence-manifest.json",
	    "storeVsaFromVersion": "1.0.0",
	    "classes": {
	      "firmware": {"bundles": ["attestations-firmware.intoto.jsonl"], "declares": [
	        {"kind": "instead", "when": "signing-key", "class": "firmware-signed", "output": "signed-class"}
	      ]},
	      "firmware-signed": {"bundles": ["attestations-firmware.intoto.jsonl"], "requestable": false},
	      "helm-chart": {"bundles": ["attestations-charts.intoto.jsonl"]}
	    }
	  }
	}`

	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestDeriveClasses(t *testing.T) {
	policy := classesPolicy(t)

	for _, tt := range []struct {
		name  string
		extra []string
		want  string
	}{
		{"nothing given", nil, "classes=helm-chart,firmware\nsigned-class=\n"},
		{
			"an input given, the class declared in place",
			[]string{"--given", "signing-key=keys/fw=1.pem"},
			"classes=helm-chart,firmware-signed\nsigned-class=firmware-signed\n",
		},
		{
			"an input given empty is not given",
			[]string{"--given", "signing-key="},
			"classes=helm-chart,firmware\nsigned-class=\n",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			args := append([]string{"derive", "classes", "--policy", policy, "--classes", "helm-chart, firmware"},
				tt.extra...)
			if code := Run(args, &stdout, &stderr); code != exitOK {
				t.Fatalf("Run = %d\nstderr: %s", code, stderr.String())
			}

			if got := stdout.String(); got != tt.want {
				t.Fatalf("stdout = %q, want %q", got, tt.want)
			}

			if !strings.Contains(stderr.String(), "the evidence declares helm-chart,") {
				t.Errorf("stderr = %q, want the declaration said", stderr.String())
			}
		})
	}
}

func TestDeriveClassesRefusals(t *testing.T) {
	policy := classesPolicy(t)

	for _, tt := range []struct {
		name string
		args []string
		code int
		says string
	}{
		{
			name: "no policy",
			args: []string{"derive", "classes", "--classes", "firmware"},
			code: exitUsage,
			says: "--policy is required",
		},
		{
			name: "an unknown flag",
			args: []string{"derive", "classes", "--conjure"},
			code: exitUsage,
			says: "flag provided but not defined",
		},
		{
			name: "a policy that is not there",
			args: []string{"derive", "classes", "--policy", filepath.Join(t.TempDir(), "absent.json"), "--classes", "x"},
			code: exitRefused,
			says: "derive classes: open ",
		},
		{
			name: "an empty request",
			args: []string{"derive", "classes", "--policy", policy},
			code: exitRefused,
			says: "no classes requested — a release that builds nothing is not a release",
		},
		{
			name: "an empty element",
			args: []string{"derive", "classes", "--policy", policy, "--classes", "firmware,,helm-chart"},
			code: exitRefused,
			says: "requested class 2 of 3 is empty",
		},
		{
			name: "a --given that is not name=value",
			args: []string{"derive", "classes", "--policy", policy, "--classes", "firmware", "--given", "signing-key"},
			code: exitUsage,
			says: `--given "signing-key" is not name=value`,
		},
		{
			name: "a --given named twice",
			args: []string{
				"derive", "classes", "--policy", policy, "--classes", "firmware",
				"--given", "signing-key=", "--given", "signing-key=k",
			},
			code: exitUsage,
			says: "--given signing-key is named twice",
		},
		{
			name: "an input given for a class not requested",
			args: []string{
				"derive", "classes", "--policy", policy, "--classes", "helm-chart", "--given", "signing-key=k",
			},
			code: exitRefused,
			says: "signing-key is declared but firmware is not among the classes — it would build nothing",
		},
		{
			name: "a class only ever derived",
			args: []string{"derive", "classes", "--policy", policy, "--classes", "firmware-signed"},
			code: exitRefused,
			says: `class "firmware-signed" is not requestable`,
		},
		{
			name: "an unknown class",
			args: []string{"derive", "classes", "--policy", policy, "--classes", "firmware,go-binary"},
			code: exitRefused,
			says: `unknown class requested: "go-binary" is not declared in evidence.classes`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			if code := Run(tt.args, &stdout, &stderr); code != tt.code {
				t.Fatalf("Run = %d, want %d\nstderr: %s", code, tt.code, stderr.String())
			}

			if !strings.Contains(stderr.String(), tt.says) {
				t.Errorf("stderr = %q, want it to say %q", stderr.String(), tt.says)
			}

			if stdout.Len() != 0 {
				t.Errorf("a refused request printed %q", stdout.String())
			}
		})
	}
}

func TestDeriveClassesOutputFailures(t *testing.T) {
	policy := classesPolicy(t)

	var stderr bytes.Buffer

	if code := Run([]string{"derive", "classes", "--policy", policy, "--classes", "firmware"},
		failWriterI{}, &stderr); code != exitIO {
		t.Fatalf("dead stdout: Run = %d, want %d", code, exitIO)
	}

	if code := Run([]string{"derive", "classes"}, failWriterI{}, failWriterI{}); code != exitIO {
		t.Fatalf("dead stderr: Run = %d, want %d", code, exitIO)
	}
}
