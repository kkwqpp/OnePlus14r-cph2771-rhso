package core

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// TargetCompactionSummary describes the compaction step, before any separately
// selected required-target repair. It contains no source file contents.
type TargetCompactionSummary struct {
	EntriesBefore  int `json:"entries_before"`
	EntriesAfter   int `json:"entries_after"`
	RemovedEntries int `json:"removed_entries"`
	PackagesBefore int `json:"packages_before"`
}

// This deliberately supports a narrower profile than the installed engine:
// android, dotted package names, and at most one trailing mode marker. The
// engine checks raw '#' comments before trimming and later packages override
// earlier ones. Rejecting every mixed-mode package preserves that ordering rule.
var compactTargetPackage = regexp.MustCompile(`^(android|[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+)$`)

func compactTargets(body []byte) ([]byte, TargetCompactionSummary, error) {
	summary := TargetCompactionSummary{}
	if len(body) > 1<<20 || !utf8.Valid(body) || strings.ContainsRune(string(body), '\x00') {
		return nil, summary, fail("E_INPUT", "Target compaction requires a bounded UTF-8 target list without NUL bytes.")
	}
	lines := strings.SplitAfter(string(body), "\n")
	modes := map[string]string{}
	keep := make([]bool, len(lines))
	for i, line := range lines {
		keep[i] = true
		content := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if strings.TrimSpace(content) == "" || strings.HasPrefix(content, "#") {
			continue
		}
		token := strings.Trim(content, " \t")
		mode := "unflagged"
		pkg := token
		if strings.HasSuffix(token, "!") || strings.HasSuffix(token, "?") {
			mode = token[len(token)-1:]
			pkg = token[:len(token)-1]
		}
		if !compactTargetPackage.MatchString(pkg) {
			return nil, TargetCompactionSummary{}, fail("E_SELECTION", "Target compaction supports android or dotted package names with one optional trailing ! or ?. Unsupported syntax must be reviewed explicitly.")
		}
		summary.EntriesBefore++
		if previous, exists := modes[pkg]; exists {
			if previous != mode {
				return nil, TargetCompactionSummary{}, fail("E_SELECTION", "A target package has conflicting modes. Compaction cannot choose a mode; review the entries explicitly.")
			}
			keep[i] = false
			summary.RemovedEntries++
		} else {
			modes[pkg] = mode
		}
	}
	summary.PackagesBefore = len(modes)
	summary.EntriesAfter = summary.EntriesBefore - summary.RemovedEntries
	var out strings.Builder
	out.Grow(len(body))
	for i, line := range lines {
		if keep[i] {
			out.WriteString(line)
		}
	}
	return []byte(out.String()), summary, nil
}

func validTargetCompaction(s *TargetCompactionSummary) bool {
	return s == nil || (s.EntriesBefore >= 0 && s.EntriesBefore <= 1<<20 && s.RemovedEntries >= 0 && s.RemovedEntries <= s.EntriesBefore && s.EntriesAfter == s.EntriesBefore-s.RemovedEntries && s.PackagesBefore == s.EntriesAfter)
}

// A set-based diff hides removal of repeated rules. Count each raw line so the
// review includes the exact occurrences removed, in their original order.
func targetLineDelta(from, to []byte) []string {
	remaining := map[string]int{}
	for _, line := range strings.Split(string(from), "\n") {
		remaining[line]++
	}
	changes := []string{}
	for _, line := range strings.Split(string(to), "\n") {
		if remaining[line] > 0 {
			remaining[line]--
		} else if line != "" {
			changes = append(changes, line)
		}
	}
	return changes
}
