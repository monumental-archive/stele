// Package workflow is the ONE reading path for GitHub Actions
// workflow files: what the FORMAT says, never what any org does with
// it. Nothing here knows an owner, a repository, a directory
// convention or a caller list — those are the reader's to declare.
//
// It exists because two legs of the engine ask the same question of
// the same bytes — "is this a reusable workflow", "what does this job
// grant" — and two readers of one format drift into a pair that
// disagree about what a file says (the .github#434 law: share the
// definition, never share the derivation).
//
// The file is parsed as YAML, by a YAML parser. The Python this
// replaces scanned lines at fixed 2/4/6-space indentation because its
// runner had no YAML library, and that assumption is an ORG
// convention baked into a scanner: a tree written at other indents,
// or with a flow mapping, reads as a different file to the scanner
// than to the platform that runs it. Reproducing the assumption in
// Go would be transliteration wearing a proof.
//
// Two shapes the line scanner could not see and this reader can:
// `permissions: read-all` (a blanket grant, which the scanner
// silently read as no grant at all) and `on: workflow_call` written
// as a scalar or a sequence item.
package workflow

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// Level is one permission scope's grant level. The three values are
// ordered — none < read < write — because the whole join is one
// comparison: a caller must hold AT LEAST what its callee's jobs ask
// for.
type Level int

// The three levels the platform defines.
const (
	LevelNone Level = iota
	LevelRead
	LevelWrite
)

// levels is the spelling-to-level map, and the refusal boundary with
// it: a level outside these three is a shape this reader does not
// understand, never a value to guess at.
//
//nolint:gochecknoglobals // a format constant; Go has no const map
var levels = map[string]Level{"none": LevelNone, "read": LevelRead, "write": LevelWrite}

// String renders the level the way the platform spells it.
func (l Level) String() string {
	switch l {
	case LevelNone:
		return "none"
	case LevelRead:
		return "read"
	case LevelWrite:
		return "write"
	default:
		return fmt.Sprintf("level(%d)", int(l))
	}
}

// File is one workflow file: the name its repository knows it by, and
// its bytes. The name is the identity — the platform requires a
// repository's workflows to live in one flat directory, so within a
// repository the file name IS the workflow.
type File struct {
	Name    string
	Content []byte
}

// Grant is one `permissions:` block. A blanket grant (`read-all`,
// `write-all`) is held separately from the enumerated scopes rather
// than expanded across them: expanding would need the platform's full
// scope vocabulary, and a vocabulary hardcoded here goes stale the
// next time the platform adds a scope — silently, in the direction
// that under-reports.
type Grant struct {
	all    Level
	scopes map[string]Level
}

// Level reports the level this grant holds for one scope: the higher
// of its enumerated entry and its blanket level.
func (g *Grant) Level(scope string) Level {
	if l, ok := g.scopes[scope]; ok && l > g.all {
		return l
	}

	return g.all
}

// All reports the blanket level — LevelNone when the grant enumerates
// its scopes, which is the usual case.
func (g *Grant) All() Level { return g.all }

// Scopes returns the enumerated scopes this grant holds above none,
// sorted. Scopes at none are absent: a grant of nothing asks nothing
// and is owed nothing.
func (g *Grant) Scopes() []string {
	out := make([]string, 0, len(g.scopes))

	for s, l := range g.scopes {
		if l > LevelNone {
			out = append(out, s)
		}
	}

	sort.Strings(out)

	return out
}

// Merge folds another grant into this one, keeping the higher level
// per scope — the union that a reusable workflow's requirement is.
func (g *Grant) Merge(other *Grant) {
	if other == nil {
		return
	}

	if other.all > g.all {
		g.all = other.all
	}

	for s, l := range other.scopes {
		if g.scopes == nil {
			g.scopes = map[string]Level{}
		}

		if l > g.scopes[s] {
			g.scopes[s] = l
		}
	}
}

// Job is one entry under `jobs:`. Uses is empty for a job that runs
// steps; Grant is nil for a job that declares no `permissions:` block
// of its own, which is distinct from one that declares an empty
// block — absent takes the workflow-level default, empty grants
// nothing.
type Job struct {
	Name  string
	Uses  string
	Grant *Grant
}

// Doc is one parsed workflow file. Jobs keep document order so a
// walk over them reports deterministically.
type Doc struct {
	// Reusable reports whether the file declares a workflow_call
	// trigger — whether anything may call it at all.
	Reusable bool
	// Grant is the workflow-level block, nil when the file declares
	// none.
	Grant *Grant
	Jobs  []Job
}

// Effective returns the grant a job runs under: its own block, or the
// workflow-level default when it declares none. A file with neither
// grants nothing THAT THIS READER CAN SEE — the platform would fall
// back to the repository's default grant, which is a repository
// setting no file states, so a static read must treat it as nothing
// rather than assume a generosity it cannot prove.
func (d *Doc) Effective(j *Job) *Grant {
	if j.Grant != nil {
		return j.Grant
	}

	if d.Grant != nil {
		return d.Grant
	}

	return &Grant{}
}

// Requirement is what a caller of this workflow must hold: the union
// of every job's effective grant.
//
// Every job, including the ones that only call another reusable
// workflow: a nested callee's ask chains up through this workflow to
// its caller, so a `uses:` job's restated grant IS part of what this
// workflow requires.
func (d *Doc) Requirement() *Grant {
	req := &Grant{}

	for i := range d.Jobs {
		req.Merge(d.Effective(&d.Jobs[i]))
	}

	return req
}

// wfFile is the decode shape. The polymorphic keys stay as nodes:
// `on` is a scalar, a sequence or a mapping, `permissions` a scalar
// or a mapping, and `jobs` a mapping whose ORDER matters to a
// deterministic walk. A zero Node means the key was absent, which is
// the distinction the whole reader turns on.
type wfFile struct {
	On          yaml.Node `yaml:"on"`
	Permissions yaml.Node `yaml:"permissions"`
	Jobs        yaml.Node `yaml:"jobs"`
}

// Parse reads one workflow file. It refuses rather than guessing:
// bytes that are not YAML, a `permissions:` shape outside the
// platform's grammar, a level spelled anything but none/read/write.
// A file the reader cannot understand is not a file that grants
// nothing.
func Parse(content []byte) (*Doc, error) {
	var f wfFile

	if err := yaml.Unmarshal(content, &f); err != nil {
		return nil, fmt.Errorf("workflow: %w", err)
	}

	// The platform does not accept YAML anchors, so a file using one
	// does not run at all. Every other key refuses an alias through
	// its own shape check; the trigger list is the one place an alias
	// would read as a quiet "not callable", so it refuses by name.
	if f.On.Kind == yaml.AliasNode {
		return nil, errors.New("workflow: on: is a YAML alias, and the platform does not accept anchors")
	}

	grant, err := parseGrant(&f.Permissions)
	if err != nil {
		return nil, fmt.Errorf("workflow: permissions: %w", err)
	}

	jobs, err := parseJobs(&f.Jobs)
	if err != nil {
		return nil, fmt.Errorf("workflow: %w", err)
	}

	return &Doc{Reusable: declaresWorkflowCall(&f.On), Grant: grant, Jobs: jobs}, nil
}

// workflowCall is the trigger name that makes a workflow callable.
const workflowCall = "workflow_call"

// declaresWorkflowCall reports whether the `on:` value names the
// workflow_call trigger, in any of the three shapes the platform
// accepts for a trigger list.
func declaresWorkflowCall(on *yaml.Node) bool {
	switch on.Kind {
	case yaml.ScalarNode:
		return on.Value == workflowCall
	case yaml.SequenceNode:
		for _, item := range on.Content {
			if item.Kind == yaml.ScalarNode && item.Value == workflowCall {
				return true
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(on.Content); i += 2 {
			if on.Content[i].Value == workflowCall {
				return true
			}
		}
	case yaml.DocumentNode, yaml.AliasNode:
	}

	return false
}

// The two blanket spellings the platform accepts in place of a
// scope mapping.
const (
	readAll  = "read-all"
	writeAll = "write-all"
)

// parseGrant reads one `permissions:` value. An absent key is nil —
// "no block", which the caller distinguishes from an empty one.
func parseGrant(n *yaml.Node) (*Grant, error) {
	switch n.Kind {
	case 0:
		return nil, nil //nolint:nilnil // nil grant, no error: an absent block IS the answer
	case yaml.ScalarNode:
		return blanketGrant(n)
	case yaml.MappingNode:
		return scopeGrant(n)
	case yaml.SequenceNode, yaml.DocumentNode, yaml.AliasNode:
	}

	return nil, errors.New("block is neither a blanket level nor a scope mapping")
}

// blanketGrant reads the scalar spellings. A null scalar — a
// `permissions:` key with nothing after it — is refused rather than
// read as the empty grant: the platform rejects it too, and guessing
// which of `{}` or "absent" a human meant is exactly the silent
// reinterpretation this reader exists to avoid.
func blanketGrant(n *yaml.Node) (*Grant, error) {
	switch {
	case n.Tag == "!!null":
		return nil, errors.New("block is empty — write `{}` to grant nothing")
	case n.Value == readAll:
		return &Grant{all: LevelRead}, nil
	case n.Value == writeAll:
		return &Grant{all: LevelWrite}, nil
	}

	return nil, fmt.Errorf("%q is not a blanket grant (%s, %s)", n.Value, readAll, writeAll)
}

// scopeGrant reads the mapping spelling. Unknown SCOPE names are
// kept: the platform adds scopes, and a scope this reader has never
// heard of is still a grant a callee can ask for. Unknown LEVELS are
// refused: there are three, and a fourth spelling is a file this
// reader cannot judge.
func scopeGrant(n *yaml.Node) (*Grant, error) {
	g := &Grant{scopes: map[string]Level{}}

	for i := 0; i+1 < len(n.Content); i += 2 {
		key, val := n.Content[i], n.Content[i+1]

		if key.Kind != yaml.ScalarNode || val.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("scope %q is not a name/level pair", key.Value)
		}

		level, ok := levels[val.Value]
		if !ok {
			return nil, fmt.Errorf("scope %q has level %q, which is not none, read or write", key.Value, val.Value)
		}

		g.scopes[key.Value] = level
	}

	return g, nil
}

// nodePairStride is how a YAML mapping node stores its entries: key,
// value, key, value.
const nodePairStride = 2

// parseJobs reads the `jobs:` mapping in document order.
func parseJobs(n *yaml.Node) ([]Job, error) {
	if n.Kind == 0 {
		return nil, nil
	}

	if n.Kind != yaml.MappingNode {
		return nil, errors.New("jobs: is not a mapping")
	}

	jobs := make([]Job, 0, len(n.Content)/nodePairStride)

	for i := 0; i+1 < len(n.Content); i += 2 {
		job, err := parseJob(n.Content[i], n.Content[i+1])
		if err != nil {
			return nil, err
		}

		jobs = append(jobs, job)
	}

	return jobs, nil
}

// parseJob reads one job's grant and the workflow it calls.
func parseJob(key, body *yaml.Node) (Job, error) {
	job := Job{Name: key.Value}

	if body.Kind != yaml.MappingNode {
		return job, fmt.Errorf("jobs.%s is not a mapping", job.Name)
	}

	for i := 0; i+1 < len(body.Content); i += 2 {
		k, v := body.Content[i], body.Content[i+1]

		switch k.Value {
		case "permissions":
			grant, err := parseGrant(v)
			if err != nil {
				return job, fmt.Errorf("jobs.%s.permissions: %w", job.Name, err)
			}

			job.Grant = grant
		case "uses":
			if v.Kind != yaml.ScalarNode {
				return job, fmt.Errorf("jobs.%s.uses is not a string", job.Name)
			}

			job.Uses = v.Value
		}
	}

	return job, nil
}

// Ref is a parsed job-level `uses:` value — the platform's grammar
// for naming a reusable workflow, and nothing above it. Which
// owner/repo is "ours" is the reader's declaration, never this
// package's.
type Ref struct {
	// Local reports the `./path` form: a workflow in the CALLER's own
	// repository. Owner and Repo are empty for it, and so is Version:
	// a local call runs the caller's own commit by definition.
	Local bool
	Owner string
	Repo  string
	// Path is the repository-relative path of the callee.
	Path string
	// Version is what follows `@` — a commit, tag or branch. The join
	// never resolves it: which tree a pin names is the caller's to
	// place, and the run judges the tree it was handed.
	Version string
}

// Name is the callee's file name — the identity within a repository,
// because the platform keeps a repository's workflows in one flat
// directory.
func (r Ref) Name() string {
	if i := strings.LastIndex(r.Path, "/"); i >= 0 {
		return r.Path[i+1:]
	}

	return r.Path
}

// pathSegments is the minimum a remote reference carries: an owner, a
// repository and at least one path segment.
const pathSegments = 3

// ParseRef reads a job-level `uses:` value. A job may only call a
// reusable workflow, so the action forms a STEP accepts (`owner/repo`
// at a ref, `docker://…`) are refusals here rather than references:
// a call this reader cannot resolve is an unchecked grant, and
// silence about it is the failure class the whole join exists to
// remove.
func ParseRef(uses string) (Ref, error) {
	s := strings.TrimSpace(uses)

	switch {
	case s == "":
		return Ref{}, errors.New("the reference is empty")
	case strings.HasPrefix(s, "docker://"):
		return Ref{}, errors.New("a container reference names an action, and a job calls a workflow")
	case strings.HasPrefix(s, "./"):
		return localRef(s)
	}

	target, version, ok := strings.Cut(s, "@")
	if !ok {
		return Ref{}, errors.New("a remote workflow call names a ref after `@`")
	}

	if version == "" {
		return Ref{}, errors.New("the ref after `@` is empty")
	}

	parts := strings.Split(target, "/")
	if len(parts) < pathSegments {
		return Ref{}, fmt.Errorf("%q names no workflow path — a job calls owner/repo/path@ref", target)
	}

	if slices.Contains(parts, "") {
		return Ref{}, fmt.Errorf("%q carries an empty path segment", target)
	}

	return Ref{
		Owner:   parts[0],
		Repo:    parts[1],
		Path:    strings.Join(parts[pathSegments-1:], "/"),
		Version: version,
	}, nil
}

// localRef reads the `./path` form.
func localRef(s string) (Ref, error) {
	if strings.Contains(s, "@") {
		return Ref{}, errors.New("a local workflow call takes no `@ref` — it runs the caller's own commit")
	}

	path := strings.TrimPrefix(s, "./")
	if path == "" {
		return Ref{}, errors.New("the local reference names no path")
	}

	return Ref{Local: true, Path: path}, nil
}
