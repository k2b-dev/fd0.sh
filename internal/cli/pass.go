package cli

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/valentinkolb/fd0.sh/internal/passitem"
	"github.com/valentinkolb/fd0.sh/internal/tui"
)

const passNamePrefix = "pass:"

type PassAddOpts struct {
	Name  string
	URL   []string
	Scope string
	Force bool
	Notes string
	Tags  []string
}

type PassNotesSetOpts struct {
	Item  string
	Scope string
	// Text is the note supplied as a positional argument. HasText
	// distinguishes "no argument given" (read stdin or open $EDITOR) from an
	// explicit empty argument (clear the note).
	Text    string
	HasText bool
}

type PassFieldSetOpts struct {
	Item     string
	Path     string
	Value    string
	Kind     string
	Secret   bool
	Generate bool
	Length   int
	Scope    string
}

type PassFileAddOpts struct {
	Item  string
	Path  string
	File  string
	MIME  string
	Scope string
}

func RunPassAdd(ctx context.Context, o PassAddOpts) error {
	name, err := normalizePassName(o.Name)
	if err != nil {
		return err
	}
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	scope, err := s.resolveScopeID(o.Scope)
	if err != nil {
		return err
	}
	if err := ensureNoDuplicate(s, scope, passNamePrefix, name, o.Force); err != nil {
		return err
	}
	item := passitem.New(name, o.URL)
	if _, err := item.SetTags(o.Tags); err != nil {
		return err
	}
	// SetNotes is a no-op for "", so the flag stays optional.
	if err := item.SetNotes(o.Notes); err != nil {
		return err
	}
	if err := item.Validate(); err != nil {
		return err
	}
	if err := s.SetTypedSecret(ctx, scope, passNamePrefix+name, passitem.TypePassItem, item.Marshal()); err != nil {
		return err
	}
	stderrln("✓ pass item %q added to %s", name, scopeName(s, scope))
	hintSyncForPeers()
	return nil
}

func RunPassList(ctx context.Context, scopeID string, jsonOut bool, filter PassTagFilter) error {
	filter, err := filter.validate()
	if err != nil {
		return err
	}
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	items, err := loadPassItems(s, scopeID)
	if err != nil {
		return err
	}
	items = filterPassTags(items, filter)
	if jsonOut {
		return json.NewEncoder(os.Stdout).Encode(passSummaryRows(s, items))
	}
	if len(items) == 0 {
		stderrln("no pass items")
		return nil
	}
	for _, it := range items {
		url := ""
		if len(it.Item.URLs) > 0 {
			url = it.Item.URLs[0]
		}
		fmt.Printf("%-24s  %-12s  %s\n", it.DisplayName(), scopeName(s, it.ScopeID), url)
	}
	return nil
}

func RunPassFind(ctx context.Context, scopeID, query, rawURL string, jsonOut bool, filter PassTagFilter) error {
	filter, err := filter.validate()
	if err != nil {
		return err
	}
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	items, err := loadPassItems(s, scopeID)
	if err != nil {
		return err
	}
	items = filterPassTags(items, filter)
	var matches []passRow
	for _, it := range items {
		if passMatches(it.Item, query, rawURL) {
			matches = append(matches, it)
		}
	}
	if jsonOut {
		return json.NewEncoder(os.Stdout).Encode(passSummaryRows(s, matches))
	}
	if len(matches) == 0 {
		stderrln("no matching pass items")
		return nil
	}
	for _, it := range matches {
		url := ""
		if len(it.Item.URLs) > 0 {
			url = it.Item.URLs[0]
		}
		fmt.Printf("%-24s  %-12s  %s\n", it.DisplayName(), scopeName(s, it.ScopeID), url)
	}
	return nil
}

func RunPassBrowse(ctx context.Context, scopeID, query string, clearAfter time.Duration, filter PassTagFilter) error {
	filter, err := filter.validate()
	if err != nil {
		return err
	}
	if !IsTTY(os.Stdin) || !IsTTY(os.Stderr) {
		return errors.New("interactive pass browser requires a TTY (or use `fd0 pass list` / `fd0 pass show NAME`)")
	}
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	items, err := loadPassItems(s, scopeID)
	if err != nil {
		return err
	}
	items = filterPassTags(items, filter)
	if len(items) == 0 {
		fmt.Fprintln(os.Stderr, "(no pass items)")
		return nil
	}
	browserItems := make([]tui.PassBrowserItem, len(items))
	byID := make(map[string]passRow, len(items))
	for i, it := range items {
		id := passBrowserID(it)
		byID[id] = it
		scopeLabel := scopeName(s, it.ScopeID)
		url := ""
		if len(it.Item.URLs) > 0 {
			url = it.Item.URLs[0]
		}
		browserItems[i] = tui.PassBrowserItem{
			ID:     id,
			Title:  it.Item.Title,
			Scope:  scopeLabel,
			URL:    url,
			Search: passBrowserSearchText(it, scopeLabel),
			Fields: passBrowserFields(it.Item.Fields, ""),
		}
	}
	res, err := tui.RunPassBrowser(browserItems, query)
	if err != nil {
		return err
	}
	if res.ItemID == "" {
		return nil
	}
	row, ok := byID[res.ItemID]
	if !ok {
		return errors.New("pass browser returned unknown item")
	}
	var path string
	switch res.Action {
	case tui.PassActionCopyPassword:
		path, err = preferredPassField(row.Item.Fields, passitem.FieldSecret, []string{"password", "pass"})
	case tui.PassActionCopyUsername:
		path, err = preferredPassField(row.Item.Fields, passitem.FieldText, []string{"username", "user", "email", "login"})
	case tui.PassActionCopyTOTP:
		_, path, err = firstTOTP(row.Item.Fields, "")
	default:
		return fmt.Errorf("unknown pass browser action %q", res.Action)
	}
	if err != nil {
		return err
	}
	f, err := row.Item.Field(path)
	if err != nil {
		return err
	}
	val, err := fieldPlainValue(*f)
	if err != nil {
		return err
	}
	return doCopy(row.Item.Title+"/"+path, val, clearAfter)
}

func RunPassShow(ctx context.Context, scopeID, name string, reveal, jsonOut bool) error {
	s, rec, item, err := openPassItem(ctx, scopeID, name)
	if err != nil {
		return err
	}
	defer s.Close()
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(item)
	}
	renderPassItem(os.Stdout, item, scopeName(s, rec.ScopeID), reveal)
	return nil
}

// renderPassItem writes the human-readable `pass show` body.
//
// It takes a writer instead of printing directly so the layout — in
// particular the notes block — is testable without capturing os.Stdout.
func renderPassItem(w io.Writer, item *passitem.Item, scopeLabel string, reveal bool) {
	fmt.Fprintf(w, "%s  [scope: %s]\n", item.Title, scopeLabel)
	if tags := item.Tags(); len(tags) > 0 {
		fmt.Fprintf(w, "  tags      %s\n", strings.Join(tags, ", "))
	}
	for _, u := range item.URLs {
		fmt.Fprintf(w, "  url       %s\n", u)
	}
	// The reserved note is rendered as its own trailing block, so it must not
	// also appear in the field list.
	if fields := passListedFields(item); len(fields) > 0 {
		fmt.Fprintln(w)
		printPassFields(w, fields, "", reveal)
	}
	printPassNotes(w, item.Notes())
}

// passListedFields returns the fields `pass show` tabulates: everything except
// the reserved top-level notes field. A field of the same name inside a section
// belongs to that section and stays in the list.
func passListedFields(item *passitem.Item) []passitem.Field {
	out := make([]passitem.Field, 0, len(item.Fields))
	for _, f := range item.Fields {
		if isPassNotesField(f) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// isPassNotesField reports whether f is the reserved note field. Callers must
// only apply it to the item's top-level fields.
func isPassNotesField(f passitem.Field) bool {
	return f.Type == passitem.FieldText && strings.EqualFold(f.Name, passitem.NotesFieldName)
}

// printPassNotes writes the trailing notes block, indented one level deeper
// than the heading so multi-line notes stay visually attached to it.
func printPassNotes(w io.Writer, notes string) {
	if notes == "" {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s\n", passitem.NotesFieldName)
	for _, line := range strings.Split(notes, "\n") {
		if line == "" {
			fmt.Fprintln(w)
			continue
		}
		fmt.Fprintf(w, "    %s\n", line)
	}
}

func RunPassRemove(ctx context.Context, scopeID, name string, yes bool) error {
	s, rec, _, err := openPassItem(ctx, scopeID, name)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := confirmDanger(yes, fmt.Sprintf("Remove pass item %q from %s?", name, scopeName(s, rec.ScopeID))); err != nil {
		return err
	}
	if err := s.RemoveTypedSecret(ctx, rec.ScopeID, rec.Name); err != nil {
		return err
	}
	stderrln("✓ pass item %q removed from %s", name, scopeName(s, rec.ScopeID))
	hintSyncForPeers()
	return nil
}

// PassEditOpts patches an item's own attributes. Fields are deliberately not
// here: `pass field set` already edits them by path, and a field can hold a
// secret, a TOTP seed or a file, which no flat flag could express.
type PassEditOpts struct {
	Name  string
	Scope string
	Title *string
	URLs  *[]string
}

// RunPassEdit changes only the attributes the user named, leaving the rest
// alone.
func RunPassEdit(ctx context.Context, o PassEditOpts) error {
	name, err := normalizePassName(o.Name)
	if err != nil {
		return err
	}
	return EditItem(ctx, KindPass, o.Scope, name,
		decodePassRecord,
		func(item *passitem.Item) (bool, error) {
			changed := false
			setString(&item.Title, o.Title, &changed)
			setStrings(&item.URLs, o.URLs, &changed)
			if changed {
				// Every other mutator stamps the item, so revision and
				// updated_at stay meaningful for this path too.
				item.Touch()
			}
			return changed, nil
		},
		func(item *passitem.Item) error { return item.Validate() },
		func(item *passitem.Item) (string, any) { return passitem.TypePassItem, item.Marshal() },
	)
}

// RunPassRename renames a pass item.
//
// The stored payload is left alone: Title is a separate, separately editable
// attribute that merely defaults to the name at creation time, so rewriting it
// here would silently discard a title the user chose.
func RunPassRename(ctx context.Context, scopeID, oldName, newName string, force bool) error {
	oldName, err := normalizePassName(oldName)
	if err != nil {
		return err
	}
	newName, err = normalizePassName(newName)
	if err != nil {
		return err
	}
	s, err := Open(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.RenameItem(ctx, KindPass, scopeID, oldName, newName, force, nil)
}

func RunPassSectionAdd(ctx context.Context, scopeID, itemName, path string) error {
	s, rec, item, err := openPassItem(ctx, scopeID, itemName)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := item.AddSection(path); err != nil {
		return err
	}
	if err := s.SetTypedSecret(ctx, rec.ScopeID, rec.Name, passitem.TypePassItem, item.Marshal()); err != nil {
		return err
	}
	stderrln("✓ section %q added to %s", path, item.Title)
	hintSyncForPeers()
	return nil
}

func RunPassFieldSet(ctx context.Context, o PassFieldSetOpts) error {
	s, rec, item, err := openPassItem(ctx, o.Scope, o.Item)
	if err != nil {
		return err
	}
	defer s.Close()
	kind := o.Kind
	if o.Secret {
		kind = passitem.FieldSecret
	}
	if kind == "" {
		kind = passitem.FieldText
	}
	if o.Generate && kind == passitem.FieldText && !o.Secret {
		kind = passitem.FieldSecret
	}
	var field passitem.Field
	switch kind {
	case passitem.FieldText, passitem.FieldSecret:
		value := o.Value
		if o.Generate {
			if kind != passitem.FieldSecret {
				return errors.New("--generate requires --type secret or --secret")
			}
			value, err = GeneratePassword(o.Length)
			if err != nil {
				return err
			}
		} else if value == "-" {
			value, err = readStdinTrimOneNewline("pass field set")
			if err != nil {
				return err
			}
		} else if value == "" {
			return errors.New("VALUE required (or use --generate / - for stdin)")
		}
		field, err = passitem.NewStringField(kind, value)
	case passitem.FieldPasskey:
		if o.Value == "" {
			return errors.New("passkey field requires JSON VALUE")
		}
		field, err = passitem.NewRawJSONField(kind, []byte(o.Value))
	default:
		return fmt.Errorf("field set supports text, secret, passkey (got %q); use totp/file/section commands for other types", kind)
	}
	if err != nil {
		return err
	}
	if err := item.SetField(o.Path, field); err != nil {
		return err
	}
	if err := s.SetTypedSecret(ctx, rec.ScopeID, rec.Name, passitem.TypePassItem, item.Marshal()); err != nil {
		return err
	}
	stderrln("✓ field %q set on %s", o.Path, item.Title)
	hintSyncForPeers()
	return nil
}

func RunPassFieldGet(ctx context.Context, scopeID, itemName, path string, raw bool) error {
	s, _, item, err := openPassItem(ctx, scopeID, itemName)
	if err != nil {
		return err
	}
	defer s.Close()
	f, err := item.Field(path)
	if err != nil {
		return err
	}
	val, err := fieldPlainValue(*f)
	if err != nil {
		return err
	}
	if raw {
		fmt.Print(val)
	} else {
		fmt.Println(val)
	}
	return nil
}

func RunPassFieldRemove(ctx context.Context, scopeID, itemName, path string, yes bool) error {
	s, rec, item, err := openPassItem(ctx, scopeID, itemName)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := confirmDanger(yes, fmt.Sprintf("Remove field %q from %s?", path, item.Title)); err != nil {
		return err
	}
	if err := item.RemoveField(path); err != nil {
		return err
	}
	if err := s.SetTypedSecret(ctx, rec.ScopeID, rec.Name, passitem.TypePassItem, item.Marshal()); err != nil {
		return err
	}
	stderrln("✓ field %q removed from %s", path, item.Title)
	hintSyncForPeers()
	return nil
}

// RunPassNotes prints the item's note to stdout. An item without a note prints
// nothing and succeeds, so `fd0 pass notes x` is safe to pipe.
func RunPassNotes(ctx context.Context, scopeID, itemName string) error {
	s, _, item, err := openPassItem(ctx, scopeID, itemName)
	if err != nil {
		return err
	}
	defer s.Close()
	notes := item.Notes()
	if notes == "" {
		return nil
	}
	fmt.Println(notes)
	return nil
}

func RunPassNotesSet(ctx context.Context, o PassNotesSetOpts) error {
	s, rec, item, err := openPassItem(ctx, o.Scope, o.Item)
	if err != nil {
		return err
	}
	defer s.Close()
	notes := o.Text
	if !o.HasText {
		// No positional: piped input when stdin is redirected, otherwise the
		// user's editor pre-loaded with the current note.
		if IsTTY(os.Stdin) {
			notes, err = editPassNotes(item.Notes())
		} else {
			notes, err = readStdinTrimOneNewline("pass notes set")
		}
		if err != nil {
			return err
		}
	}
	if err := applyPassNotes(ctx, s, rec, item, notes); err != nil {
		return err
	}
	if item.Notes() == "" {
		stderrln("✓ note removed from %s", item.Title)
	} else {
		stderrln("✓ note set on %s", item.Title)
	}
	hintSyncForPeers()
	return nil
}

func RunPassNotesRemove(ctx context.Context, scopeID, itemName string, yes bool) error {
	s, rec, item, err := openPassItem(ctx, scopeID, itemName)
	if err != nil {
		return err
	}
	defer s.Close()
	if item.Notes() == "" {
		return fmt.Errorf("%s has no note", item.Title)
	}
	if err := confirmDanger(yes, fmt.Sprintf("Remove the note from %s?", item.Title)); err != nil {
		return err
	}
	if err := applyPassNotes(ctx, s, rec, item, ""); err != nil {
		return err
	}
	stderrln("✓ note removed from %s", item.Title)
	hintSyncForPeers()
	return nil
}

// setPassNotes applies notes to item and readies it for persistence.
//
// SetNotes, unlike SetField, neither bumps item metadata nor re-validates, so
// both happen here — without Validate an over-long note would be written and
// then refuse to decode on the way back out.
func setPassNotes(item *passitem.Item, notes string) error {
	// SetNotes stamps and validates on its own, as SetField does.
	return item.SetNotes(notes)
}

// applyPassNotes writes notes onto item and persists it through the same
// SetTypedSecret path every other pass mutation uses.
func applyPassNotes(ctx context.Context, s *Session, rec *TypedRecord, item *passitem.Item, notes string) error {
	if err := setPassNotes(item, notes); err != nil {
		return err
	}
	return s.SetTypedSecret(ctx, rec.ScopeID, rec.Name, passitem.TypePassItem, item.Marshal())
}

// editPassNotes opens the user's editor on initial and returns what they saved.
//
// The note is plaintext, so the scratch file is created 0600 by os.CreateTemp
// (O_EXCL, in $TMPDIR — per-user on macOS) and removed on every exit path,
// including a failed or aborted editor run.
func editPassNotes(initial string) (string, error) {
	f, err := os.CreateTemp("", "fd0-notes-*.txt")
	if err != nil {
		return "", fmt.Errorf("pass notes set: temp file: %w", err)
	}
	path := f.Name()
	defer func() { _ = os.Remove(path) }()
	// CreateTemp already uses 0600; restate it so a permissive umask or a
	// future change to that default cannot widen the plaintext note.
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("pass notes set: temp file: %w", err)
	}
	// Seed with exactly one trailing newline so line-oriented editors do not
	// report a missing final newline; the result is trimmed again below.
	seed := strings.TrimRight(initial, "\n")
	if seed != "" {
		seed += "\n"
	}
	if _, err := io.WriteString(f, seed); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("pass notes set: temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("pass notes set: temp file: %w", err)
	}
	if err := runEditor(path); err != nil {
		return "", err
	}
	buf, err := os.ReadFile(path) // #nosec G304 -- path is our own os.CreateTemp file.
	if err != nil {
		return "", fmt.Errorf("pass notes set: read editor buffer: %w", err)
	}
	return strings.TrimRight(string(buf), "\n"), nil
}

// runEditor runs $EDITOR (then $VISUAL, then vi) on path.
//
// The editor string is split on whitespace rather than handed to a shell, so
// "code --wait" works while nothing in the value can be interpreted as shell
// syntax.
func runEditor(path string) error {
	editor := ""
	for _, key := range []string{"EDITOR", "VISUAL"} {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			editor = v
			break
		}
	}
	if editor == "" {
		editor = "vi"
	}
	argv := strings.Fields(editor)
	if len(argv) == 0 {
		return errors.New("pass notes set: empty editor command")
	}
	// #nosec G204,G702 -- $EDITOR/$VISUAL is local user configuration, no less
	// trusted than the fd0 binary itself, and the only appended argument is our
	// own os.CreateTemp path. No shell is involved, so the value cannot expand.
	cmd := exec.Command(argv[0], append(argv[1:], path)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pass notes set: editor %q: %w", editor, err)
	}
	return nil
}

func RunPassCopy(ctx context.Context, scopeID, itemName, path string, clearAfter time.Duration) error {
	s, _, item, err := openPassItem(ctx, scopeID, itemName)
	if err != nil {
		return err
	}
	defer s.Close()
	if path == "" {
		path, err = preferredPassField(item.Fields, passitem.FieldSecret, []string{"password", "pass"})
		if err != nil {
			return err
		}
	}
	f, err := item.Field(path)
	if err != nil {
		return err
	}
	val, err := fieldPlainValue(*f)
	if err != nil {
		return err
	}
	return doCopy(item.Title+"/"+path, val, clearAfter)
}

func RunPassTOTPAdd(ctx context.Context, scopeID, itemName, path, uri string) error {
	if path == "" {
		path = "totp"
	}
	v, err := passitem.ParseTOTPURI(uri)
	if err != nil {
		return err
	}
	field, err := passitem.NewTOTPField(v)
	if err != nil {
		return err
	}
	s, rec, item, err := openPassItem(ctx, scopeID, itemName)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := item.SetField(path, field); err != nil {
		return err
	}
	if err := s.SetTypedSecret(ctx, rec.ScopeID, rec.Name, passitem.TypePassItem, item.Marshal()); err != nil {
		return err
	}
	stderrln("✓ TOTP field %q added to %s", path, item.Title)
	hintSyncForPeers()
	return nil
}

func RunPassTOTP(ctx context.Context, scopeID, itemName, path string, raw bool) error {
	s, _, item, err := openPassItem(ctx, scopeID, itemName)
	if err != nil {
		return err
	}
	defer s.Close()
	var f *passitem.Field
	if path != "" {
		f, err = item.Field(path)
	} else {
		f, path, err = firstTOTP(item.Fields, "")
	}
	if err != nil {
		return err
	}
	v, err := passitem.TOTPFromField(*f)
	if err != nil {
		return err
	}
	code, remaining, err := passitem.TOTPCode(v, time.Now())
	if err != nil {
		return err
	}
	if raw {
		fmt.Print(code)
	} else {
		fmt.Printf("%s  (%ds, %s)\n", code, remaining, path)
	}
	return nil
}

func RunPassFileAdd(ctx context.Context, o PassFileAddOpts) error {
	if o.File == "" {
		return errors.New("pass file add: FILE required")
	}
	data, err := safeReadConfigFile(o.File, passitem.MaxFileBytes)
	if err != nil {
		return err
	}
	fieldPath := o.Path
	if fieldPath == "" {
		fieldPath = filepath.Base(o.File)
	}
	field, err := passitem.NewFileField(fieldPath, o.MIME, data)
	if err != nil {
		return err
	}
	s, rec, item, err := openPassItem(ctx, o.Scope, o.Item)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := item.SetField(fieldPath, field); err != nil {
		return err
	}
	if err := s.SetTypedSecret(ctx, rec.ScopeID, rec.Name, passitem.TypePassItem, item.Marshal()); err != nil {
		return err
	}
	stderrln("✓ file %q attached as %q on %s", o.File, fieldPath, item.Title)
	hintSyncForPeers()
	return nil
}

func RunPassFileExport(ctx context.Context, scopeID, itemName, path, out string, force bool) error {
	s, _, item, err := openPassItem(ctx, scopeID, itemName)
	if err != nil {
		return err
	}
	defer s.Close()
	f, err := item.Field(path)
	if err != nil {
		return err
	}
	file, err := passitem.FileFromField(*f)
	if err != nil {
		return err
	}
	data, err := passitem.DecodeFileData(file)
	if err != nil {
		return err
	}
	out, err = passFileExportPath(file.Name, out)
	if err != nil {
		return err
	}
	if err := writePassFileExport(out, data, force); err != nil {
		return err
	}
	stderrln("✓ wrote %s (%d bytes)", out, len(data))
	return nil
}

func passFileExportPath(storedName, out string) (string, error) {
	name, err := passitem.SafeFileName(storedName)
	if err != nil {
		return "", fmt.Errorf("pass file export: unsafe stored file name: %w", err)
	}
	if out != "" {
		return out, nil
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("pass file export: current directory: %w", err)
	}
	target := filepath.Join(dir, name)
	rel, err := filepath.Rel(dir, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("pass file export: stored file name escapes destination")
	}
	return target, nil
}

func writePassFileExport(path string, data []byte, force bool) error {
	if force {
		if err := writeFileAtomic(path, data, 0o600); err != nil {
			return fmt.Errorf("pass file export %s: %w", path, err)
		}
		return nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s exists (pass --force to overwrite)", path)
		}
		return fmt.Errorf("pass file export %s: %w", path, err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("pass file export %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("pass file export %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("pass file export %s: %w", path, err)
	}
	complete = true
	return nil
}

func RunPassGenerate(length int, raw bool) error {
	pass, err := GeneratePassword(length)
	if err != nil {
		return err
	}
	if raw {
		fmt.Print(pass)
	} else {
		fmt.Println(pass)
	}
	return nil
}

func GeneratePassword(length int) (string, error) {
	if length == 0 {
		length = 32
	}
	if length < 12 || length > 256 {
		return "", fmt.Errorf("password length must be 12..256")
	}
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+[]{}:,.?"
	buf := make([]byte, length)
	max := big.NewInt(int64(len(alphabet)))
	for i := range buf {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		buf[i] = alphabet[n.Int64()]
	}
	return string(buf), nil
}

type passRow struct {
	ScopeID string         `json:"scopeId"`
	Name    string         `json:"name"`
	Item    *passitem.Item `json:"item"`
}

type passSummaryRow struct {
	ScopeID string             `json:"scopeId"`
	Scope   string             `json:"scope"`
	Name    string             `json:"name"`
	Title   string             `json:"title"`
	URLs    []string           `json:"urls,omitempty"`
	Fields  []passSummaryField `json:"fields,omitempty"`
	Tags    []string           `json:"tags,omitempty"`
}

type passSummaryField struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

func (r passRow) DisplayName() string {
	return strings.TrimPrefix(r.Name, passNamePrefix)
}

func passSummaryRows(s *Session, rows []passRow) []passSummaryRow {
	out := make([]passSummaryRow, len(rows))
	for i, row := range rows {
		out[i] = passSummaryRow{
			ScopeID: row.ScopeID,
			Scope:   scopeLabelOf(s, row.ScopeID),
			Name:    row.DisplayName(),
			Title:   row.Item.Title,
			URLs:    append([]string(nil), row.Item.URLs...),
			Fields:  passSummaryFields(row.Item.Fields, ""),
			Tags:    row.Item.Tags(),
		}
	}
	return out
}

func passSummaryFields(fields []passitem.Field, prefix string) []passSummaryField {
	var out []passSummaryField
	for _, f := range fields {
		path := f.Name
		if prefix != "" {
			path = prefix + "/" + f.Name
		}
		out = append(out, passSummaryField{Path: path, Type: f.Type})
		if f.Type == passitem.FieldSection {
			out = append(out, passSummaryFields(f.Fields, path)...)
		}
	}
	return out
}

func passBrowserID(r passRow) string {
	return r.ScopeID + "\x00" + r.Name
}

func passBrowserSearchText(r passRow, scopeLabel string) string {
	parts := []string{r.Item.Title, r.DisplayName(), scopeLabel, r.ScopeID}
	parts = append(parts, r.Item.URLs...)
	parts = append(parts, r.Item.Tags()...)
	return strings.Join(parts, " ")
}

func loadPassItems(s *Session, scopeID string) ([]passRow, error) {
	rows, err := s.ListTypedSecrets(scopeID, passitem.TypePassItem)
	if err != nil {
		return nil, err
	}
	out := make([]passRow, 0, len(rows))
	for _, r := range rows {
		item, err := decodePassRecord(r)
		if err != nil {
			stderrln("  ! malformed pass item %q in scope %s: %v", strings.TrimPrefix(r.Name, passNamePrefix), scopeName(s, r.ScopeID), err)
			continue
		}
		out = append(out, passRow{ScopeID: r.ScopeID, Name: r.Name, Item: item})
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Item.Title) < strings.ToLower(out[j].Item.Title)
	})
	return out, nil
}

func openPassItem(ctx context.Context, scopeID, name string) (*Session, *TypedRecord, *passitem.Item, error) {
	name, err := normalizePassName(name)
	if err != nil {
		return nil, nil, nil, err
	}
	s, err := Open(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	rec, err := s.GetTypedSecret(scopeID, passNamePrefix+name)
	if err != nil {
		s.Close()
		return nil, nil, nil, err
	}
	if rec.Type != passitem.TypePassItem {
		s.Close()
		return nil, nil, nil, fmt.Errorf("%q is %s, not %s", name, rec.Type, passitem.TypePassItem)
	}
	item, err := decodePassRecord(*rec)
	if err != nil {
		s.Close()
		return nil, nil, nil, err
	}
	return s, rec, item, nil
}

func normalizePassName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("pass item NAME required")
	}
	return name, nil
}

func decodePassRecord(r TypedRecord) (*passitem.Item, error) {
	raw, err := r.PayloadJSON()
	if err != nil {
		return nil, err
	}
	return passitem.Decode(raw)
}

func passMatches(item *passitem.Item, query, rawURL string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	if rawURL != "" {
		return passMatchesURL(item, rawURL)
	}
	if query == "" {
		return true
	}
	if strings.Contains(strings.ToLower(item.Title), query) {
		return true
	}
	for _, tag := range item.Tags() {
		if strings.Contains(passitem.TagKey(tag), passitem.TagKey(query)) {
			return true
		}
	}
	for _, u := range item.URLs {
		if strings.Contains(strings.ToLower(u), query) {
			return true
		}
	}
	return false
}

func passMatchesURL(item *passitem.Item, raw string) bool {
	targetHost := hostForMatch(raw)
	if targetHost == "" {
		return false
	}
	for _, u := range item.URLs {
		host := hostForMatch(u)
		if host == "" {
			continue
		}
		if targetHost == host || strings.HasSuffix(targetHost, "."+host) {
			return true
		}
	}
	return false
}

func hostForMatch(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func printPassFields(w io.Writer, fields []passitem.Field, prefix string, reveal bool) {
	for _, f := range fields {
		path := f.Name
		if prefix != "" {
			path = prefix + "/" + f.Name
		}
		fmt.Fprintf(w, "  %-28s %-8s %s\n", path, f.Type, passitem.FieldValueSummary(f, reveal))
		if f.Type == passitem.FieldSection {
			printPassFields(w, f.Fields, path, reveal)
		}
	}
}

func passBrowserFields(fields []passitem.Field, prefix string) []tui.PassBrowserField {
	var out []tui.PassBrowserField
	for _, f := range fields {
		path := f.Name
		if prefix != "" {
			path = prefix + "/" + f.Name
		}
		out = append(out, tui.PassBrowserField{
			Path:     path,
			Type:     f.Type,
			Masked:   passitem.FieldValueSummary(f, false),
			Revealed: passitem.FieldValueSummary(f, true),
		})
		if f.Type == passitem.FieldSection {
			out = append(out, passBrowserFields(f.Fields, path)...)
		}
	}
	return out
}

func fieldPlainValue(f passitem.Field) (string, error) {
	switch f.Type {
	case passitem.FieldText, passitem.FieldSecret:
		return passitem.StringValue(f)
	case passitem.FieldTOTP:
		v, err := passitem.TOTPFromField(f)
		if err != nil {
			return "", err
		}
		code, _, err := passitem.TOTPCode(v, time.Now())
		return code, err
	default:
		return "", fmt.Errorf("field %q has type %s; cannot print/copy as text", f.Name, f.Type)
	}
}

func preferredPassField(fields []passitem.Field, kind string, names []string) (string, error) {
	type candidate struct {
		path string
		rank int
	}
	var candidates []candidate
	var walk func([]passitem.Field, string)
	walk = func(fs []passitem.Field, prefix string) {
		for _, f := range fs {
			path := f.Name
			if prefix != "" {
				path = prefix + "/" + f.Name
			}
			if f.Type == passitem.FieldSection {
				walk(f.Fields, path)
				continue
			}
			if f.Type != kind {
				continue
			}
			leaf := strings.ToLower(f.Name)
			rank := 100
			for i, name := range names {
				if leaf == name {
					rank = i
					break
				}
				if strings.Contains(leaf, name) && rank == 100 {
					rank = 50 + i
				}
			}
			candidates = append(candidates, candidate{path: path, rank: rank})
		}
	}
	walk(fields, "")
	if len(candidates) == 0 {
		return "", fmt.Errorf("no %s field found", kind)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].rank != candidates[j].rank {
			return candidates[i].rank < candidates[j].rank
		}
		return candidates[i].path < candidates[j].path
	})
	return candidates[0].path, nil
}

func firstTOTP(fields []passitem.Field, prefix string) (*passitem.Field, string, error) {
	for i := range fields {
		path := fields[i].Name
		if prefix != "" {
			path = prefix + "/" + fields[i].Name
		}
		if fields[i].Type == passitem.FieldTOTP {
			return &fields[i], path, nil
		}
		if fields[i].Type == passitem.FieldSection {
			f, p, err := firstTOTP(fields[i].Fields, path)
			if err == nil {
				return f, p, nil
			}
		}
	}
	return nil, "", errors.New("no TOTP field found")
}

func readStdinTrimOneNewline(op string) (string, error) {
	buf, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("%s: read stdin: %w", op, err)
	}
	if n := len(buf); n > 0 && buf[n-1] == '\n' {
		buf = buf[:n-1]
	}
	return string(buf), nil
}
