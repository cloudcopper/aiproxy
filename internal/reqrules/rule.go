package reqrules

import (
	"fmt"

	"github.com/bmatcuk/doublestar/v4"
)

// Rule is a single request matching rule for whitelist/blacklist matching.
//
// All fields except ID are optional. Absent (zero-value) fields match anything.
// A request must satisfy ALL present fields for the rule to match.
//
// Port constraint: at most one of Port, PortRange, PortRanges may be set.
// PortRange nil means absent — same as not setting Port.
type Rule struct {
	ID         string   `json:"id"`
	Comment    string   `json:"comment,omitempty"`
	Method     string   `json:"method,omitempty"`
	Scheme     string   `json:"scheme,omitempty"`
	Host       string   `json:"host,omitempty"`
	Path       string   `json:"path,omitempty"`
	Port       int      `json:"port,omitempty"`
	PortRange  *[2]int  `json:"port_range,omitempty"` // nil = absent
	PortRanges [][2]int `json:"port_ranges,omitempty"`
	RPM        int      `json:"rpm,omitempty"`
	Priority   int      `json:"priority,omitempty"`

	// Runtime marks this rule as proxy-managed (loaded from whitelist2/blacklist2).
	// true  → WebUI may edit/delete this rule.
	// false → rule is static (user-managed file), WebUI shows it read-only.
	// Never serialized to JSON (json:"-").
	Runtime bool `json:"-"`

	// slashHost is the pre-computed dot-to-slash transformation of Host,
	// used for efficient doublestar glob matching in the hot loop.
	// Set by ReqRules.Add; not serialized (unexported field).
	slashHost slashHost
}

// Validate checks if the Rule is valid.
// Returns an error if the rule is invalid.
func (rule Rule) Validate() error {
	if rule.ID == "" {
		return fmt.Errorf("rule id is required")
	}

	if rule.Method != "" && !isValidHTTPMethod(rule.Method) {
		return fmt.Errorf("invalid HTTP method: %s", rule.Method)
	}

	if rule.Scheme != "" && rule.Scheme != "http" && rule.Scheme != "https" {
		return fmt.Errorf("invalid scheme %q: must be \"http\" or \"https\"", rule.Scheme)
	}

	if rule.Host != "" && !doublestar.ValidatePattern(rule.Host) {
		return fmt.Errorf("invalid host glob pattern: %s", rule.Host)
	}

	if rule.Path != "" && !doublestar.ValidatePattern(rule.Path) {
		return fmt.Errorf("invalid path glob pattern: %s", rule.Path)
	}

	// At most one of Port, PortRange, PortRanges may be set.
	portFields := 0
	if rule.Port != 0 {
		portFields++
	}
	if rule.PortRange != nil {
		portFields++
	}
	if rule.PortRanges != nil {
		portFields++
	}
	if portFields > 1 {
		return fmt.Errorf("at most one of port, port_range, port_ranges may be set")
	}

	if rule.PortRange != nil {
		if err := validatePortRange(*rule.PortRange); err != nil {
			return fmt.Errorf("invalid port_range: %w", err)
		}
	}

	if rule.PortRanges != nil {
		if len(rule.PortRanges) == 0 {
			return fmt.Errorf("port_ranges must not be empty; omit to match any port")
		}
		for i, pr := range rule.PortRanges {
			if err := validatePortRange(pr); err != nil {
				return fmt.Errorf("invalid port_ranges[%d]: %w", i, err)
			}
		}
	}

	if rule.RPM < 0 {
		return fmt.Errorf("rpm must be non-negative, got %d", rule.RPM)
	}

	if rule.Priority < 0 {
		return fmt.Errorf("priority must be non-negative, got %d", rule.Priority)
	}

	return nil
}

// validatePortRange checks that a [2]int port range has valid bounds.
func validatePortRange(pr [2]int) error {
	if pr[0] <= 0 {
		return fmt.Errorf("low bound %d must be > 0", pr[0])
	}
	if pr[1] <= 0 {
		return fmt.Errorf("high bound %d must be > 0", pr[1])
	}
	if pr[0] > pr[1] {
		return fmt.Errorf("low %d must be <= high %d", pr[0], pr[1])
	}
	return nil
}

// isValidHTTPMethod reports whether method is a valid HTTP method.
func isValidHTTPMethod(method string) bool {
	switch method {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT":
		return true
	}
	return false
}
