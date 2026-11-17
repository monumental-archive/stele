package gitrepo

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// The git objects a tag or chain walk judges: tag refs, tag objects
// with their signature material, the chain notes, and the commit
// facts genesis derivation needs (stele#384). Read here, from a
// repository the caller prepared, because git is the one way stele
// reads git objects: a second reader of the same fact — the forge's
// per-object REST API, which this replaced — is a second answer that
// can disagree with the first.
//
// Every read is plumbing over the object store. None of them needs a
// tree or a source blob, which is what lets them run over a
// repository fetched commits-only: the only blobs such a repository
// holds are its notes.

// TagRef is one tag ref: its short name, the object it points at,
// and whether that object is an annotated tag.
type TagRef struct {
	Name      string
	ObjectSHA string
	Annotated bool
}

// TagObject is one annotated tag's substance: the tagger name, the
// object it targets, and the signature material — Payload is the tag
// object with the signature block removed, Signature the block
// itself, both nil when the tag is unsigned.
type TagObject struct {
	Tagger    string
	Target    string
	Payload   []byte
	Signature []byte
}

// ChainNote is one note blob keyed by the revision it annotates.
//
// Note is the blob's BYTES, and the type says so (stele#193). A note
// is whatever git stores at that path: chain links are JSON, and the
// same ledgers carry plain-text scaffolding notes beside them. Every
// consumer takes these bytes and decides for itself whether they parse
// (a link) or not (scaffolding); none may assume.
type ChainNote struct {
	Rev  string
	Note []byte
}

// CommitMeta is what genesis derivation needs of one commit: its
// parents and its committer time, with the first line of its message.
type CommitMeta struct {
	Parents     []string
	CommitEpoch int64
	// Subject is the first line of the commit message.
	Subject string
}

// signatureRE opens a signature block inside a tag object: the
// OpenPGP, X.509 (gitsign, CMS) and SSH forms git itself recognises.
var signatureRE = regexp.MustCompile(`^-----BEGIN (?:PGP SIGNATURE|PGP MESSAGE|SIGNED MESSAGE|SSH SIGNATURE)-----`)

// TagRefs lists every tag ref, in ref-name order — the order git
// itself keeps them in.
func (r *Repo) TagRefs() ([]TagRef, error) {
	out, err := r.git("for-each-ref", "--format=%(objecttype) %(objectname) %(refname)", "refs/tags")
	if err != nil {
		return nil, fmt.Errorf("gitrepo: listing tags: %w", err)
	}

	return parseTagRefs(out)
}

// parseTagRefs reads the tag listing TagRefs asks for.
func parseTagRefs(out []byte) ([]TagRef, error) {
	var refs []TagRef

	for line := range strings.Lines(string(out)) {
		// A ref name cannot carry a space (git check-ref-format), so the
		// three fields split cleanly.
		const tagColumns = 3

		fields := strings.Fields(line)
		if len(fields) != tagColumns || !revRE.MatchString(fields[1]) || !strings.HasPrefix(fields[2], "refs/tags/") {
			return nil, fmt.Errorf("gitrepo: tag listing line %q is not the requested format", strings.TrimSpace(line))
		}

		refs = append(refs, TagRef{
			Name:      strings.TrimPrefix(fields[2], "refs/tags/"),
			ObjectSHA: fields[1],
			Annotated: fields[0] == "tag",
		})
	}

	return refs, nil
}

// TagObject reads one annotated tag object.
//
// The signature split is git's own: the block starts at the LAST line
// that opens one of the markers, and everything before it is what the
// signature covers. Measured against the forge's own reading of the
// same tag (stele#384): the payload and signature it served were
// byte-identical to this split, and an unsigned tag served neither.
func (r *Repo) TagObject(sha string) (*TagObject, error) {
	if !revRE.MatchString(sha) {
		return nil, fmt.Errorf("gitrepo: tag object %q is not a full object id", sha)
	}

	raw, err := r.git("cat-file", "tag", sha)
	if err != nil {
		return nil, fmt.Errorf("gitrepo: tag object %s: %w", sha, err)
	}

	return parseTagObject(sha, raw)
}

// parseTagObject reads one raw tag object: the headers up to the
// first blank line, then the message the signature block ends.
func parseTagObject(sha string, raw []byte) (*TagObject, error) {
	head, _, _ := bytes.Cut(raw, []byte("\n\n"))

	obj := &TagObject{}

	for line := range strings.Lines(string(head)) {
		key, value, _ := strings.Cut(strings.TrimRight(line, "\n"), " ")

		switch key {
		case "object":
			obj.Target = value
		case "tagger":
			// "Name <email> epoch tz": the name is everything before the
			// address, which git forbids inside a name.
			if name, _, found := strings.Cut(value, " <"); found {
				obj.Tagger = name
			}
		}
	}

	if !revRE.MatchString(obj.Target) || obj.Tagger == "" {
		return nil, fmt.Errorf("gitrepo: tag object %s: missing tagger or target", sha)
	}

	if at := signatureStart(raw); at >= 0 {
		obj.Payload, obj.Signature = raw[:at], raw[at:]
	}

	return obj, nil
}

// signatureStart is the offset of the last line opening a signature
// block, or -1 when the object carries none.
func signatureStart(raw []byte) int {
	at := -1

	for pos := 0; pos < len(raw); {
		line := raw[pos:]
		if eol := bytes.IndexByte(line, '\n'); eol >= 0 {
			line = line[:eol+1]
		}

		if signatureRE.Match(line) {
			at = pos
		}

		pos += len(line)
	}

	return at
}

// ResolveTag resolves one tag ref to the object it targets: a
// lightweight tag names its target directly, an annotated one through
// its tag object, which is returned beside it (nil marks lightweight).
//
// This is the ONE place a tag becomes its target. The tag audit reads
// every tag through it, and TagCommit — the pin the full-depth leg
// verifies identities against — asks it too, so the two cannot come to
// disagree about what a tag points at.
func (r *Repo) ResolveTag(ref TagRef) (string, *TagObject, error) {
	if !ref.Annotated {
		return ref.ObjectSHA, nil, nil
	}

	obj, err := r.TagObject(ref.ObjectSHA)
	if err != nil {
		return "", nil, err
	}

	return obj.Target, obj, nil
}

// TagCommit resolves one tag, by name, to the object it targets —
// through ResolveTag, the one resolution.
func (r *Repo) TagCommit(name string) (string, error) {
	refs, err := r.TagRefs()
	if err != nil {
		return "", err
	}

	for _, ref := range refs {
		if ref.Name != name {
			continue
		}

		target, _, err := r.ResolveTag(ref)

		return target, err
	}

	return "", fmt.Errorf("gitrepo: no tag %s", name)
}

// ChainNotes reads every note on the notes ref with the revision it
// annotates, in the order git keeps them. An absent notes ref is an
// empty chain — an answer, not an error, exactly as Noted reads it.
//
// The blobs come out of one cat-file batch rather than one process per
// note: a ledger is hundreds of notes, and the bytes are the same
// bytes Note reads one at a time.
func (r *Repo) ChainNotes() ([]ChainNote, error) {
	if r.notesRef == "" {
		return nil, errNoLedger
	}

	if _, err := r.git("rev-parse", "--verify", "--quiet", r.notesRef); err != nil {
		return nil, nil //nolint:nilerr // an absent notes ref is an empty ledger, judged by the engine
	}

	out, err := r.git("notes", "--ref", r.notesRef, "list")
	if err != nil {
		return nil, fmt.Errorf("gitrepo: notes list: %w", err)
	}

	notes, blobs, err := parseNotesList(out)
	if err != nil {
		return nil, err
	}

	contents, err := r.blobs(blobs)
	if err != nil {
		return nil, err
	}

	for i := range notes {
		notes[i].Note = contents[i]
	}

	return notes, nil
}

// parseNotesList reads `notes list`, which prints one
// "<note blob> <annotated object>" pair per line, into the notes (bytes
// still to come) and the blobs to read for them, in the same order.
func parseNotesList(out []byte) ([]ChainNote, []string, error) {
	var (
		notes []ChainNote
		blobs []string
	)

	for line := range strings.Lines(string(out)) {
		const listColumns = 2

		fields := strings.Fields(line)
		if len(fields) != listColumns || !revRE.MatchString(fields[0]) || !revRE.MatchString(fields[1]) {
			return nil, nil, fmt.Errorf("gitrepo: notes list line %q is not a blob and a revision",
				strings.TrimSpace(line))
		}

		notes = append(notes, ChainNote{Rev: fields[1]})
		blobs = append(blobs, fields[0])
	}

	return notes, blobs, nil
}

// blobs reads many blobs through one `cat-file --batch`, in the order
// asked. A missing object, or one that is not a blob, refuses the
// whole read: a ledger read with a hole in it is not a ledger.
func (r *Repo) blobs(oids []string) ([][]byte, error) {
	if len(oids) == 0 {
		return nil, nil
	}

	out, err := r.gitIn([]byte(strings.Join(oids, "\n")+"\n"), "cat-file", "--batch")
	if err != nil {
		return nil, fmt.Errorf("gitrepo: reading note blobs: %w", err)
	}

	rd := bufio.NewReader(bytes.NewReader(out))
	got := make([][]byte, 0, len(oids))

	for _, oid := range oids {
		content, berr := batchEntry(rd, oid)
		if berr != nil {
			return nil, berr
		}

		got = append(got, content)
	}

	return got, nil
}

// batchEntry reads one `cat-file --batch` record: the header
// "<oid> <type> <size>", the content, and its terminating newline.
func batchEntry(rd *bufio.Reader, oid string) ([]byte, error) {
	header, err := rd.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("gitrepo: blob %s: the batch ended early: %w", oid, err)
	}

	const headerColumns = 3

	fields := strings.Fields(header)
	if len(fields) != headerColumns || fields[0] != oid || fields[1] != "blob" {
		return nil, fmt.Errorf("gitrepo: blob %s: the store answered %q", oid, strings.TrimSpace(header))
	}

	size, err := strconv.Atoi(fields[2])
	if err != nil || size < 0 {
		return nil, fmt.Errorf("gitrepo: blob %s: size %q", oid, fields[2])
	}

	content := make([]byte, size+1) // the content and its newline
	if _, err := io.ReadFull(rd, content); err != nil {
		return nil, fmt.Errorf("gitrepo: blob %s: the batch ended early: %w", oid, err)
	}

	if content[size] != '\n' {
		return nil, fmt.Errorf("gitrepo: blob %s: the batch record is not terminated", oid)
	}

	return content[:size], nil
}

// CommitMeta reads one commit's parents, committer time and subject
// from the commit object itself — never a porcelain command, which
// would reach for the commit's tree, and a repository fetched
// commits-only has none.
func (r *Repo) CommitMeta(rev string) (*CommitMeta, error) {
	raw, err := r.git("cat-file", "commit", rev)
	if err != nil {
		return nil, fmt.Errorf("gitrepo: commit %s: %w", rev, err)
	}

	return parseCommit(rev, raw)
}

// parseCommit reads one raw commit object: the headers up to the first
// blank line — continuation lines of a multi-line header such as a
// signature carry no key and are passed over — then the message.
func parseCommit(rev string, raw []byte) (*CommitMeta, error) {
	head, message, _ := bytes.Cut(raw, []byte("\n\n"))

	meta := &CommitMeta{}
	committed := false

	for line := range strings.Lines(string(head)) {
		key, value, _ := strings.Cut(strings.TrimRight(line, "\n"), " ")

		switch key {
		case "parent":
			meta.Parents = append(meta.Parents, value)
		case "committer":
			epoch, perr := identEpoch(value)
			if perr != nil {
				return nil, fmt.Errorf("gitrepo: commit %s: committer %w", rev, perr)
			}

			meta.CommitEpoch, committed = epoch, true
		}
	}

	if !committed {
		return nil, fmt.Errorf("gitrepo: commit %s: %w", rev, errNoCommitter)
	}

	meta.Subject, _, _ = strings.Cut(string(message), "\n")

	return meta, nil
}

// errNoCommitter is a commit object with no committer line — not a
// commit git would have written.
var errNoCommitter = errors.New("the object carries no committer")

// identEpoch reads the timestamp out of an identity line's value,
// "Name <email> epoch tz".
func identEpoch(ident string) (int64, error) {
	_, after, found := strings.Cut(ident, "> ")
	if !found {
		return 0, fmt.Errorf("%q names no time", ident)
	}

	stamp, _, _ := strings.Cut(after, " ")

	epoch, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("time %q: %w", stamp, err)
	}

	return epoch, nil
}
