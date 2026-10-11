package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// MemoDisplay decodes a hex-encoded memo and returns a printable form: the
// quoted UTF-8 text when it is safe to show on one line, otherwise the uppercase
// hex. Returns "" for an empty/invalid memo. Mirrors the core's memo rendering.
func MemoDisplay(memoHex string) string {
	if memoHex == "" {
		return ""
	}
	b, err := hex.DecodeString(memoHex)
	if err != nil || len(b) == 0 {
		return ""
	}
	// Trim trailing NUL padding (memo fields are fixed-size).
	end := len(b)
	for end > 0 && b[end-1] == 0 {
		end--
	}
	b = b[:end]
	if len(b) == 0 {
		return ""
	}
	if utf8.Valid(b) {
		printable := true
		for _, r := range string(b) {
			if r == '\n' || r == '\r' || !unicode.IsPrint(r) {
				printable = false
				break
			}
		}
		if printable {
			return strconv.QuoteToASCII(string(b))
		}
	}
	return strings.ToUpper(memoHex)
}

func ColorizeJSON(s string, noColor bool) string {
	if noColor {
		return s
	}

	// keys cyan, strings and true green, numbers amber, false pink, rest dim
	green, cyan, amber, pink, dim, reset := Palette(false)

	var out strings.Builder
	i, n := 0, len(s)

	// stack tracks '{' (object) or '[' (array) so we know if next string is a key
	stack := []byte{}
	nextIsKey := false

	for i < n {
		ch := s[i]
		switch {
		case ch == '{' || ch == '[':
			out.WriteString(dim + string(ch) + reset)
			stack = append(stack, ch)
			nextIsKey = ch == '{'
			i++
		case ch == '}' || ch == ']':
			out.WriteString(dim + string(ch) + reset)
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			nextIsKey = false
			i++
		case ch == ':':
			out.WriteString(dim + ":" + reset)
			nextIsKey = false
			i++
		case ch == ',':
			out.WriteString(dim + "," + reset)
			if len(stack) > 0 && stack[len(stack)-1] == '{' {
				nextIsKey = true
			}
			i++
		case ch == '"':
			j := i + 1
			for j < n {
				if s[j] == '\\' {
					j += 2
					continue
				}
				if s[j] == '"' {
					break
				}
				j++
			}
			str := s[i : j+1]
			if nextIsKey {
				out.WriteString(cyan + str + reset)
			} else {
				out.WriteString(green + str + reset)
			}
			nextIsKey = false
			i = j + 1
		case i+4 <= n && s[i:i+4] == "true":
			out.WriteString(green + "true" + reset)
			i += 4
		case i+5 <= n && s[i:i+5] == "false":
			out.WriteString(pink + "false" + reset)
			i += 5
		case i+4 <= n && s[i:i+4] == "null":
			out.WriteString(dim + "null" + reset)
			i += 4
		case ch == '-' || (ch >= '0' && ch <= '9'):
			j := i
			for j < n && (s[j] == '-' || s[j] == '+' || s[j] == '.' || s[j] == 'e' || s[j] == 'E' || (s[j] >= '0' && s[j] <= '9')) {
				j++
			}
			out.WriteString(amber + s[i:j] + reset)
			i = j
		default:
			out.WriteByte(ch)
			i++
		}
	}
	return out.String()
}

// The CLI palette. Every command uses these colors and nothing else.
// Green is mainnet and success, cyan is testnet and info, amber is a
// warning, pink is an error, dim gray is secondary text.
const (
	ansiGreen = "\033[38;2;170;255;0m"
	ansiCyan  = "\033[38;2;0;170;255m"
	ansiAmber = "\033[38;2;255;170;0m"
	ansiPink  = "\033[38;2;255;0;170m"
	ansiDim   = "\033[38;2;160;160;160m"
	ansiReset = "\033[0m"
)

// Palette returns green, cyan, amber, pink, dim and reset, or empty strings
// when color is off.
func Palette(noColor bool) (green, cyan, amber, pink, dim, reset string) {
	if noColor {
		return "", "", "", "", "", ""
	}
	return ansiGreen, ansiCyan, ansiAmber, ansiPink, ansiDim, ansiReset
}

// NetColor is the accent for a network: green for mainnet, cyan for testnet.
func NetColor(net Network, noColor bool) string {
	if noColor {
		return ""
	}
	if net == Testnet {
		return ansiCyan
	}
	return ansiGreen
}

func head(color, label string, noColor bool) string {
	if noColor {
		return "# " + label
	}
	return color + "#" + ansiReset + " " + label
}

func SectionHead(label string, noColor bool) string { return head(ansiGreen, label, noColor) }
func ErrorHead(label string, noColor bool) string   { return head(ansiPink, label, noColor) }
func WarnHead(label string, noColor bool) string    { return head(ansiAmber, label, noColor) }

// NetHead is a section heading in the network's accent color.
func NetHead(net Network, label string, noColor bool) string {
	if noColor {
		return "# " + label
	}
	return NetColor(net, noColor) + "#" + ansiReset + " " + label
}

// Warnf prints an indented amber warning line to stderr.
func Warnf(format string, args ...any) {
	_, _, amber, _, _, reset := Palette(NoColor)
	fmt.Fprintf(os.Stderr, "  %swarning:%s %s\n", amber, reset, fmt.Sprintf(format, args...))
}

// Plural returns "1 issue" or "3 issues". Pass the plural when it is not word+"s".
func Plural(n int, word string, plural ...string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, word)
	}
	if len(plural) > 0 {
		return fmt.Sprintf("%d %s", n, plural[0])
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// YesNo prints a bool for people.
func YesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

var ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*m")

// VisibleLen is the length of s on screen, without color codes.
func VisibleLen(s string) int {
	return utf8.RuneCountInString(ansiRe.ReplaceAllString(s, ""))
}

// PadRight pads s with spaces to width w on screen. Color codes do not count.
func PadRight(s string, w int) string {
	if n := VisibleLen(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}

// PadLeft right-aligns s in width w on screen. Color codes do not count.
func PadLeft(s string, w int) string {
	if n := VisibleLen(s); n < w {
		return strings.Repeat(" ", w-n) + s
	}
	return s
}

// ExtraArgs returns an error when a command got more arguments than it takes.
func ExtraArgs(args []string, max int, usage string) error {
	if len(args) > max {
		return fmt.Errorf("too many arguments: %s (usage: %s)", strings.Join(args[max:], " "), usage)
	}
	return nil
}

func FormatAmount(atomicUnits uint64) string {
	whole := atomicUnits / 100_000_000
	frac := atomicUnits % 100_000_000
	if frac == 0 {
		return fmt.Sprintf("%d BNT", whole)
	}
	fracStr := fmt.Sprintf("%08d", frac)
	fracStr = strings.TrimRight(fracStr, "0")
	return fmt.Sprintf("%d.%s BNT", whole, fracStr)
}

// ParseAmount reads a BNT amount such as "1.5", "1.5 BNT" or "2bnt" and
// returns atomic units. It rejects zero, negative numbers and more than 8
// decimal places.
func ParseAmount(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if len(s) >= 3 && strings.EqualFold(s[len(s)-3:], "bnt") {
		s = strings.TrimSpace(s[:len(s)-3])
	}
	if s == "" {
		return 0, fmt.Errorf("missing amount: use a number like 1.5")
	}
	bad := fmt.Errorf("invalid amount %q: use a number like 1.5", s)
	if strings.ContainsAny(s, "+-eE, ") {
		return 0, bad
	}

	parts := strings.Split(s, ".")
	if len(parts) > 2 || (parts[0] == "" && (len(parts) == 1 || parts[1] == "")) {
		return 0, bad
	}

	var whole uint64
	if parts[0] != "" {
		var err error
		whole, err = strconv.ParseUint(parts[0], 10, 64)
		if errors.Is(err, strconv.ErrRange) {
			return 0, fmt.Errorf("amount too large")
		}
		if err != nil {
			return 0, bad
		}
	}

	const atomicPerBNT uint64 = 100_000_000
	if whole > (^uint64(0))/atomicPerBNT {
		return 0, fmt.Errorf("amount too large")
	}
	result := whole * atomicPerBNT

	if len(parts) == 2 && parts[1] != "" {
		fracStr := parts[1]
		if len(fracStr) > 8 {
			return 0, fmt.Errorf("too many decimal places in %q (max 8)", s)
		}
		fracStr += strings.Repeat("0", 8-len(fracStr))
		frac, err := strconv.ParseUint(fracStr, 10, 64)
		if err != nil {
			return 0, bad
		}
		if result > (^uint64(0))-frac {
			return 0, fmt.Errorf("amount too large")
		}
		result += frac
	}

	if result == 0 {
		return 0, fmt.Errorf("amount must be more than 0")
	}
	return result, nil
}

// FormatDuration prints a duration as "1h 5m", "12m" or "45s". Negative is "0s".
func FormatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Round(time.Second).Seconds()))
	}
	d = d.Round(time.Minute)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}

// SanitizeInput strips non-printable ASCII from user input (fixes
// tmux/terminal copy-paste artifacts).
func SanitizeInput(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 32 && r < 127 {
			return r
		}
		return -1
	}, s)
}
