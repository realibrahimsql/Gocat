package readline

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/fatih/color"
	"golang.org/x/term"
)

// EditMode represents the editing mode (emacs or vi)
type EditMode int

const (
	EmacsMode EditMode = iota
	ViInsertMode
	ViCommandMode
)

// SyntaxHighlighter is a function that colorizes input
type SyntaxHighlighter func(input string) string

// Editor represents a readline editor with rlwrap-like features
type Editor struct {
	reader         *bufio.Reader
	history        []string
	prompt         string
	remotePrefix   string
	historyIndex   int
	currentLine    []rune
	cursorPos      int
	originalState  *term.State
	fd             int
	completions    []string
	completionFn   func(string) []string
	historyFile    string
	maxHistory     int
	filters        []Filter
	colorPrompt    bool
	promptColor    *color.Color
	ignoreCase     bool
	wordBreakChars string

	// Advanced features
	editMode          EditMode
	undoStack         []undoState
	redoStack         []undoState
	killRing          []string
	killRingIndex     int
	syntaxHighlighter SyntaxHighlighter
	multiLine         bool
	bracketMatching   bool
	autoSuggestion    bool
	aliases           map[string]string
	macros            map[rune]string
	recordingMacro    bool
	currentMacro      []rune
	macroKey          rune
	mark              int // For selection
	yankPos           int
	hintFn            func(string) string
	validatorFn       func(string) bool
	outMu             sync.Mutex
}

// undoState stores state for undo/redo
type undoState struct {
	line      []rune
	cursorPos int
}

// Filter represents an input/output filter similar to rlwrap filters
type Filter interface {
	ProcessInput(input string) string
	ProcessOutput(output string) string
	ProcessPrompt(prompt string) string
}

// CompletionResult represents a completion match
type CompletionResult struct {
	Text        string
	Description string
	Type        string
}

// NewEditor creates a new readline editor with rlwrap-like features
func NewEditor() *Editor {
	fd := int(os.Stdin.Fd())
	originalState, _ := term.GetState(fd)

	return &Editor{
		reader:          bufio.NewReader(os.Stdin),
		history:         make([]string, 0),
		prompt:          ">> ",
		historyIndex:    -1,
		currentLine:     make([]rune, 0),
		cursorPos:       0,
		originalState:   originalState,
		fd:              fd,
		completions:     make([]string, 0),
		maxHistory:      1000,
		filters:         make([]Filter, 0),
		colorPrompt:     true,
		promptColor:     color.New(color.FgYellow, color.Bold),
		wordBreakChars:  " \t\n\r\f\v",
		editMode:        EmacsMode,
		undoStack:       make([]undoState, 0),
		redoStack:       make([]undoState, 0),
		killRing:        make([]string, 0),
		aliases:         make(map[string]string),
		macros:          make(map[rune]string),
		mark:            -1,
		bracketMatching: true,
		autoSuggestion:  true,
	}
}

// SetPrompt sets the prompt string with optional color
func (e *Editor) SetPrompt(prompt string) {
	e.prompt = prompt
}

// SetPromptColor enables/disables colored prompt
func (e *Editor) SetPromptColor(enabled bool, c *color.Color) {
	e.colorPrompt = enabled
	if c != nil {
		e.promptColor = c
	}
}

// SetHistoryFile sets the history file path for persistent history
func (e *Editor) SetHistoryFile(path string) {
	e.historyFile = path
	e.loadHistory()
}

// SetMaxHistory sets the maximum number of history entries
func (e *Editor) SetMaxHistory(max int) {
	e.maxHistory = max
}

// AddFilter adds an input/output filter
func (e *Editor) AddFilter(filter Filter) {
	e.filters = append(e.filters, filter)
}

// SetCompletionFunction sets a custom completion function
func (e *Editor) SetCompletionFunction(fn func(string) []string) {
	e.completionFn = fn
}

// AddCompletion adds a static completion word
func (e *Editor) AddCompletion(word string) {
	e.completions = append(e.completions, word)
}

// SetCompletions sets the list of completion words
func (e *Editor) SetCompletions(words []string) {
	e.completions = make([]string, len(words))
	copy(e.completions, words)
}

// ErrTerminated is returned when the editor must exit the whole program
// (SIGTERM/SIGHUP). Unlike "interrupted" (Ctrl+C cancels the current line),
// callers must unwind and return instead of continuing the input loop.
var ErrTerminated = errors.New("terminated")

// Readline reads a line from stdin with rlwrap-like features
func (e *Editor) Readline() (string, error) {
	// Check if we're in a terminal (interactive mode) or not (test mode)
	if !term.IsTerminal(e.fd) {
		// Non-interactive mode (tests) - use simple line reading
		line, err := e.reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		// Remove trailing newline and carriage return
		line = strings.TrimRight(line, "\r\n")
		if line != "" {
			e.AddHistoryEntry(line)
		}
		return line, nil
	}

	// Interactive mode - use rlwrap-like features
	// Setup signal handling: SIGINT cancels the current line, while
	// SIGTERM/SIGHUP terminate the whole program (callers must exit on
	// ErrTerminated instead of continuing the input loop).
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigChan)

	// Reset editor state
	e.currentLine = make([]rune, 0)
	e.cursorPos = 0
	e.historyIndex = -1

	// Enable raw mode for character-by-character input
	if err := e.enableRawMode(); err != nil {
		return "", fmt.Errorf("failed to enable raw mode: %v", err)
	}
	defer e.disableRawMode()

	// Display prompt with filters and colors
	prompt := e.processPrompt(e.prompt)
	e.displayPrompt(prompt)

	for {
		select {
		case sig := <-sigChan:
			// Handle Ctrl+C
			fmt.Print("\n")
			if sig == syscall.SIGTERM || sig == syscall.SIGHUP {
				return "", ErrTerminated
			}
			return "", fmt.Errorf("interrupted")
		default:
			// Read character
			ch, err := e.readChar()
			if err != nil {
				if err == io.EOF {
					return "", io.EOF
				}
				return "", err
			}

			switch ch {
			case 13: // Enter
				fmt.Print("\n")
				line := string(e.currentLine)
				processedLine := e.expandAlias(e.processInput(line))
				if processedLine != "" {
					e.AddHistoryEntry(processedLine)
				}
				return processedLine, nil

			case 3: // Ctrl+C
				fmt.Print("\n")
				return "", fmt.Errorf("interrupted")

			case 4: // Ctrl+D (EOF)
				if len(e.currentLine) == 0 {
					return "", io.EOF
				}

			case 9: // Tab (completion)
				e.handleCompletion()

			case 18: // Ctrl+R (reverse search)
				e.reverseSearch()

			case 12: // Ctrl+L (clear screen)
				e.clearScreen()

			case 1: // Ctrl+A (beginning of line)
				e.cursorPos = 0
				e.refreshLine()

			case 5: // Ctrl+E (end of line)
				e.cursorPos = len(e.currentLine)
				e.refreshLine()

			case 11: // Ctrl+K (kill to end of line)
				e.currentLine = e.currentLine[:e.cursorPos]
				e.refreshLine()

			case 21: // Ctrl+U (kill to beginning of line)
				killed := string(e.currentLine[:e.cursorPos])
				e.AddToKillRing(killed)
				e.saveUndo()
				e.currentLine = e.currentLine[e.cursorPos:]
				e.cursorPos = 0
				e.refreshLine()

			case 23: // Ctrl+W (kill word backward)
				e.killWordBackward()

			case 25: // Ctrl+Y (yank from kill ring)
				e.YankFromKillRing()

			case 26: // Ctrl+Z (undo)
				e.Undo()

			case 24: // Ctrl+X prefix
				ch2, err := e.readChar()
				if err == nil {
					switch ch2 {
					case 21: // Ctrl+X Ctrl+U (undo)
						e.Undo()
					case 5: // Ctrl+X Ctrl+E (edit in editor - not implemented)
					}
				}

			case 20: // Ctrl+T (transpose chars)
				e.TransposeChars()

			case 127, 8: // Backspace
				e.backspace()

			case 27: // Escape sequence (arrow keys, etc.)
				if e.handleEscapeSequence() {
					continue
				}

			default:
				if e.editMode == ViCommandMode && e.handleViCommand(ch) {
					continue
				}
				if unicode.IsPrint(rune(ch)) {
					e.insertChar(rune(ch))
				}
			}
		}
	}
}

// PrintAbove prints a message above the readline prompt without tearing
// the line being typed: it clears the current line, prints the message,
// then redraws the prompt, buffer and cursor position.
func (e *Editor) PrintAbove(s string) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Print(s)
		return
	}
	e.outMu.Lock()
	fmt.Print("\r\033[K")
	if !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	fmt.Print(strings.ReplaceAll(s, "\n", "\r\n"))
	e.outMu.Unlock()
	e.refreshLine()
}

// SetRemotePrefix sets a prefix rendered before the prompt on the same
// line (e.g. a remote shell prompt without trailing newline). Complete
// output lines still go above via PrintAbove; only the trailing fragment
// stays inline so typed input follows the prompt instead of dropping
// underneath it.
func (e *Editor) SetRemotePrefix(s string) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return
	}
	e.outMu.Lock()
	e.remotePrefix = s
	e.outMu.Unlock()
	e.refreshLine()
}

// AddHistoryEntry adds a command to history with deduplication
func (e *Editor) AddHistoryEntry(entry string) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return
	}

	// Remove duplicate if it exists
	for i, h := range e.history {
		if h == entry {
			e.history = append(e.history[:i], e.history[i+1:]...)
			break
		}
	}

	// Add to end
	e.history = append(e.history, entry)

	// Trim history if too long
	if len(e.history) > e.maxHistory {
		e.history = e.history[len(e.history)-e.maxHistory:]
	}

	// Save to file if configured
	if e.historyFile != "" {
		e.saveHistory()
	}
}

// GetHistory returns a copy of the command history
func (e *Editor) GetHistory() []string {
	historyCopy := make([]string, len(e.history))
	copy(historyCopy, e.history)
	return historyCopy
}

// ClearHistory clears the command history
func (e *Editor) ClearHistory() {
	e.history = make([]string, 0)
	if e.historyFile != "" {
		e.saveHistory()
	}
}

// enableRawMode enables raw terminal mode for character-by-character input
func (e *Editor) enableRawMode() error {
	_, err := term.MakeRaw(e.fd)
	return err
}

// disableRawMode restores original terminal mode
func (e *Editor) disableRawMode() {
	if e.originalState != nil {
		if err := term.Restore(e.fd, e.originalState); err != nil {
			// Log error but don't fail, as this is cleanup code
			fmt.Fprintf(os.Stderr, "Warning: failed to restore terminal state: %v\n", err)
		}
	}
}

// readChar reads a single character from stdin with timeout
func (e *Editor) readChar() (byte, error) {
	buf := make([]byte, 1)
	_, err := os.Stdin.Read(buf)
	return buf[0], err
}

// displayPrompt displays the prompt with optional coloring
func (e *Editor) displayPrompt(prompt string) {
	e.outMu.Lock()
	defer e.outMu.Unlock()
	e.displayPromptLocked(prompt)
}

func (e *Editor) displayPromptLocked(prompt string) {
	if e.colorPrompt && e.promptColor != nil {
		e.promptColor.Print(prompt)
	} else {
		fmt.Print(prompt)
	}
}

// insertChar inserts a character at the current cursor position
func (e *Editor) insertChar(ch rune) {
	if e.cursorPos == len(e.currentLine) {
		e.currentLine = append(e.currentLine, ch)
	} else {
		e.currentLine = append(e.currentLine[:e.cursorPos+1], e.currentLine[e.cursorPos:]...)
		e.currentLine[e.cursorPos] = ch
	}
	e.cursorPos++
	e.refreshLine()
}

// backspace removes the character before the cursor
func (e *Editor) backspace() {
	if e.cursorPos > 0 {
		e.currentLine = append(e.currentLine[:e.cursorPos-1], e.currentLine[e.cursorPos:]...)
		e.cursorPos--
		e.refreshLine()
	}
}

// killWordBackward removes the word before the cursor
func (e *Editor) killWordBackward() {
	if e.cursorPos == 0 {
		return
	}

	// Find the start of the current word
	start := e.cursorPos - 1
	for start > 0 && strings.ContainsRune(e.wordBreakChars, e.currentLine[start]) {
		start--
	}
	for start > 0 && !strings.ContainsRune(e.wordBreakChars, e.currentLine[start-1]) {
		start--
	}

	// Remove the word
	e.currentLine = append(e.currentLine[:start], e.currentLine[e.cursorPos:]...)
	e.cursorPos = start
	e.refreshLine()
}

// refreshLine redraws the current line with proper cursor positioning
func (e *Editor) refreshLine() {
	e.outMu.Lock()
	defer e.outMu.Unlock()
	// Clear current line
	fmt.Print("\r\033[K")
	// Redraw remote prefix (e.g. shell prompt fragment), prompt and line
	if e.remotePrefix != "" {
		fmt.Print(e.remotePrefix)
	}
	prompt := e.processPrompt(e.prompt)
	e.displayPromptLocked(prompt)

	// Apply syntax highlighting if available
	lineStr := string(e.currentLine)
	if e.syntaxHighlighter != nil {
		lineStr = e.syntaxHighlighter(lineStr)
	}

	// Apply bracket matching
	if e.bracketMatching {
		lineStr = e.highlightBrackets(string(e.currentLine))
	}

	fmt.Print(lineStr)

	// Show auto-suggestion in dim color
	if e.autoSuggestion {
		suggestion := e.getAutoSuggestion()
		if suggestion != "" {
			dimColor := color.New(color.FgHiBlack)
			dimColor.Print(suggestion)
			// Move cursor back
			fmt.Printf("\033[%dD", len([]rune(suggestion)))
		}
	}

	// Show hint if available
	if e.hintFn != nil {
		hint := e.hintFn(string(e.currentLine))
		if hint != "" {
			hintColor := color.New(color.FgHiBlack, color.Italic)
			fmt.Print(" ")
			hintColor.Print(hint)
			// Move cursor back
			fmt.Printf("\033[%dD", len([]rune(hint))+1)
		}
	}

	// Position cursor
	if e.cursorPos < len(e.currentLine) {
		fmt.Printf("\033[%dD", len(e.currentLine)-e.cursorPos)
	}
}

// clearScreen clears the terminal screen
func (e *Editor) clearScreen() {
	e.outMu.Lock()
	fmt.Print("\033[2J\033[H")
	e.outMu.Unlock()
	prompt := e.processPrompt(e.prompt)
	e.displayPrompt(prompt)
	fmt.Print(string(e.currentLine))
	if e.cursorPos < len(e.currentLine) {
		fmt.Printf("\033[%dD", len(e.currentLine)-e.cursorPos)
	}
}

// handleEscapeSequence handles arrow keys and other escape sequences
func (e *Editor) handleEscapeSequence() bool {
	// Read the next character
	ch1, err := e.readChar()
	if err != nil {
		return false
	}

	switch ch1 {
	case '[':
		// Read the third character
		ch2, err := e.readChar()
		if err != nil {
			return false
		}

		switch ch2 {
		case 'A': // Up arrow
			e.historyUp()
			return true
		case 'B': // Down arrow
			e.historyDown()
			return true
		case 'C': // Right arrow
			e.cursorRight()
			return true
		case 'D': // Left arrow
			e.cursorLeft()
			return true
		case 'H': // Home
			e.cursorPos = 0
			e.refreshLine()
			return true
		case 'F': // End
			e.cursorPos = len(e.currentLine)
			e.refreshLine()
			return true
		case '3': // Delete key
			// Read the ~ character
			if ch3, err := e.readChar(); err == nil && ch3 == '~' {
				e.deleteChar()
			}
			return true
		case '1':
			// Home key: ESC[1~
			if ch3, err := e.readChar(); err == nil && ch3 == '~' {
				e.cursorPos = 0
				e.refreshLine()
			}
			return true
		case '4':
			// End key: ESC[4~
			if ch3, err := e.readChar(); err == nil && ch3 == '~' {
				e.cursorPos = len(e.currentLine)
				e.refreshLine()
			}
			return true
		}
	case 'O':
		// Read the third character
		ch2, err := e.readChar()
		if err != nil {
			return false
		}

		switch ch2 {
		case 'H': // Home
			e.cursorPos = 0
			e.refreshLine()
			return true
		case 'F': // End
			e.cursorPos = len(e.currentLine)
			e.refreshLine()
			return true
		}
	case 'b': // Alt+B (word backward)
		e.wordBackward()
		return true
	case 'f': // Alt+F (word forward)
		e.wordForward()
		return true
	case 'd': // Alt+D (kill word forward)
		e.killWordForward()
		return true
	case 'u': // Alt+U (uppercase word)
		e.UppercaseWord()
		return true
	case 'l': // Alt+L (lowercase word)
		e.LowercaseWord()
		return true
	case 'c': // Alt+C (capitalize word)
		e.CapitalizeWord()
		return true
	case 't': // Alt+T (transpose words)
		e.TransposeWords()
		return true
	case 'y': // Alt+Y (yank pop)
		e.YankPop()
		return true
	case '.': // Alt+. (insert last argument)
		e.insertLastArgument()
		return true
	case 127: // Alt+Backspace (kill word backward)
		e.killWordBackward()
		return true
	}
	return false
}

// killWordForward removes the word after the cursor
func (e *Editor) killWordForward() {
	if e.cursorPos >= len(e.currentLine) {
		return
	}
	e.saveUndo()
	start := e.cursorPos
	// Skip whitespace
	for e.cursorPos < len(e.currentLine) && strings.ContainsRune(e.wordBreakChars, e.currentLine[e.cursorPos]) {
		e.cursorPos++
	}
	// Skip word
	for e.cursorPos < len(e.currentLine) && !strings.ContainsRune(e.wordBreakChars, e.currentLine[e.cursorPos]) {
		e.cursorPos++
	}
	killed := string(e.currentLine[start:e.cursorPos])
	e.AddToKillRing(killed)
	e.currentLine = append(e.currentLine[:start], e.currentLine[e.cursorPos:]...)
	e.cursorPos = start
	e.refreshLine()
}

// insertLastArgument inserts the last argument from previous command
func (e *Editor) insertLastArgument() {
	if len(e.history) == 0 {
		return
	}
	lastCmd := e.history[len(e.history)-1]
	words := strings.Fields(lastCmd)
	if len(words) == 0 {
		return
	}
	lastArg := words[len(words)-1]
	e.saveUndo()
	for _, ch := range lastArg {
		e.insertCharNoRefresh(ch)
	}
	e.refreshLine()
}

// deleteChar deletes the character at the cursor position
func (e *Editor) deleteChar() {
	if e.cursorPos < len(e.currentLine) {
		e.currentLine = append(e.currentLine[:e.cursorPos], e.currentLine[e.cursorPos+1:]...)
		e.refreshLine()
	}
}

// wordBackward moves cursor to the beginning of the previous word
func (e *Editor) wordBackward() {
	if e.cursorPos == 0 {
		return
	}

	// Skip whitespace
	for e.cursorPos > 0 && strings.ContainsRune(e.wordBreakChars, e.currentLine[e.cursorPos-1]) {
		e.cursorPos--
	}
	// Skip word characters
	for e.cursorPos > 0 && !strings.ContainsRune(e.wordBreakChars, e.currentLine[e.cursorPos-1]) {
		e.cursorPos--
	}
	e.refreshLine()
}

// wordForward moves cursor to the beginning of the next word
func (e *Editor) wordForward() {
	if e.cursorPos >= len(e.currentLine) {
		return
	}

	// Skip word characters
	for e.cursorPos < len(e.currentLine) && !strings.ContainsRune(e.wordBreakChars, e.currentLine[e.cursorPos]) {
		e.cursorPos++
	}
	// Skip whitespace
	for e.cursorPos < len(e.currentLine) && strings.ContainsRune(e.wordBreakChars, e.currentLine[e.cursorPos]) {
		e.cursorPos++
	}
	e.refreshLine()
}

// historyUp navigates to previous history entry
func (e *Editor) historyUp() {
	if len(e.history) == 0 {
		return
	}

	if e.historyIndex == -1 {
		e.historyIndex = len(e.history) - 1
	} else if e.historyIndex > 0 {
		e.historyIndex--
	}

	e.currentLine = []rune(e.history[e.historyIndex])
	e.cursorPos = len(e.currentLine)
	e.refreshLine()
}

// historyDown navigates to next history entry
func (e *Editor) historyDown() {
	if len(e.history) == 0 || e.historyIndex == -1 {
		return
	}

	if e.historyIndex < len(e.history)-1 {
		e.historyIndex++
		e.currentLine = []rune(e.history[e.historyIndex])
	} else {
		e.historyIndex = -1
		e.currentLine = make([]rune, 0)
	}

	e.cursorPos = len(e.currentLine)
	e.refreshLine()
}

// cursorLeft moves cursor left
func (e *Editor) cursorLeft() {
	if e.cursorPos > 0 {
		e.cursorPos--
		e.refreshLine()
	}
}

// cursorRight moves cursor right
func (e *Editor) cursorRight() {
	if e.cursorPos < len(e.currentLine) {
		e.cursorPos++
		e.refreshLine()
	}
}

// handleCompletion handles tab completion
func (e *Editor) handleCompletion() {
	currentWord := e.getCurrentWord()
	if currentWord == "" {
		return
	}

	matches := e.getCompletions(currentWord)
	if len(matches) == 0 {
		return
	}

	if len(matches) == 1 {
		// Single match - complete it
		e.completeWord(matches[0])
	} else {
		// Multiple matches - show them
		e.showCompletions(matches)
	}
}

// getCurrentWord gets the current word being typed
func (e *Editor) getCurrentWord() string {
	if e.cursorPos == 0 {
		return ""
	}

	// Find word boundaries
	start := e.cursorPos - 1
	for start > 0 && !strings.ContainsRune(e.wordBreakChars, e.currentLine[start-1]) {
		start--
	}

	return string(e.currentLine[start:e.cursorPos])
}

// getCompletions gets completion matches for a word
func (e *Editor) getCompletions(word string) []string {
	var matches []string

	// Use custom completion function if available
	if e.completionFn != nil {
		matches = append(matches, e.completionFn(word)...)
	}

	// Add static completions
	for _, completion := range e.completions {
		if e.matchesCompletion(word, completion) {
			matches = append(matches, completion)
		}
	}

	// Add history-based completions
	for _, histEntry := range e.history {
		words := strings.Fields(histEntry)
		for _, histWord := range words {
			if e.matchesCompletion(word, histWord) {
				// Avoid duplicates
				found := false
				for _, match := range matches {
					if match == histWord {
						found = true
						break
					}
				}
				if !found {
					matches = append(matches, histWord)
				}
			}
		}
	}

	// Sort matches
	sort.Strings(matches)
	return matches
}

// matchesCompletion checks if a word matches a completion
func (e *Editor) matchesCompletion(word, completion string) bool {
	if e.ignoreCase {
		return strings.HasPrefix(strings.ToLower(completion), strings.ToLower(word))
	}
	return strings.HasPrefix(completion, word)
}

// completeWord completes the current word
func (e *Editor) completeWord(completion string) {
	currentWord := e.getCurrentWord()
	if currentWord == "" {
		return
	}

	// Replace current word with completion
	start := e.cursorPos - len([]rune(currentWord))
	e.currentLine = append(e.currentLine[:start], append([]rune(completion), e.currentLine[e.cursorPos:]...)...)
	e.cursorPos = start + len([]rune(completion))
	e.refreshLine()
}

// showCompletions displays available completions
func (e *Editor) showCompletions(matches []string) {
	fmt.Print("\n")
	for i, match := range matches {
		fmt.Printf("%s", match)
		if i < len(matches)-1 {
			fmt.Print("  ")
		}
		if (i+1)%8 == 0 { // 8 completions per line
			fmt.Print("\n")
		}
	}
	if len(matches)%8 != 0 {
		fmt.Print("\n")
	}
	e.refreshLine()
}

// reverseSearch implements Ctrl+R reverse history search
func (e *Editor) reverseSearch() {
	fmt.Print("\n(reverse-i-search): ")
	searchTerm := ""
	searchResults := []string{}

	for {
		ch, err := e.readChar()
		if err != nil {
			break
		}

		switch ch {
		case 13: // Enter - select current result
			if len(searchResults) > 0 {
				e.currentLine = []rune(searchResults[0])
				e.cursorPos = len(e.currentLine)
			}
			fmt.Print("\n")
			e.refreshLine()
			return

		case 27: // Escape - cancel search
			fmt.Print("\n")
			e.refreshLine()
			return

		case 127, 8: // Backspace
			if len(searchTerm) > 0 {
				searchTerm = searchTerm[:len(searchTerm)-1]
			}

		default:
			if unicode.IsPrint(rune(ch)) {
				searchTerm += string(rune(ch))
			}
		}

		// Update search results
		searchResults = e.searchHistory(searchTerm)

		// Display current search
		fmt.Print("\r\033[K")
		fmt.Printf("(reverse-i-search): %s", searchTerm)
		if len(searchResults) > 0 {
			fmt.Printf(" [%s]", searchResults[0])
		}
	}
}

// searchHistory searches through history for matching entries
func (e *Editor) searchHistory(term string) []string {
	var results []string
	if term == "" {
		return results
	}

	// Search backwards through history
	for i := len(e.history) - 1; i >= 0; i-- {
		entry := e.history[i]
		if e.ignoreCase {
			if strings.Contains(strings.ToLower(entry), strings.ToLower(term)) {
				results = append(results, entry)
			}
		} else {
			if strings.Contains(entry, term) {
				results = append(results, entry)
			}
		}
	}

	return results
}

// processInput processes input through filters
func (e *Editor) processInput(input string) string {
	result := input
	for _, filter := range e.filters {
		result = filter.ProcessInput(result)
	}
	return result
}

// processPrompt processes prompt through filters
func (e *Editor) processPrompt(prompt string) string {
	result := prompt
	for _, filter := range e.filters {
		result = filter.ProcessPrompt(result)
	}
	return result
}

// loadHistory loads history from file
func (e *Editor) loadHistory() {
	if e.historyFile == "" {
		return
	}

	file, err := os.Open(e.historyFile)
	if err != nil {
		return // File doesn't exist yet
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			e.history = append(e.history, line)
		}
	}

	// Trim to max history
	if len(e.history) > e.maxHistory {
		e.history = e.history[len(e.history)-e.maxHistory:]
	}
}

// saveHistory saves history to file
func (e *Editor) saveHistory() {
	if e.historyFile == "" {
		return
	}

	file, err := os.Create(e.historyFile)
	if err != nil {
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, entry := range e.history {
		fmt.Fprintln(writer, entry)
	}
	writer.Flush()
}

// Simple password filter that hides password prompts
type PasswordFilter struct {
	patterns []*regexp.Regexp
}

// NewPasswordFilter creates a new password filter
func NewPasswordFilter(patterns []string) *PasswordFilter {
	pf := &PasswordFilter{
		patterns: make([]*regexp.Regexp, 0, len(patterns)),
	}

	for _, pattern := range patterns {
		if re, err := regexp.Compile(pattern); err == nil {
			pf.patterns = append(pf.patterns, re)
		}
	}

	return pf
}

func (pf *PasswordFilter) ProcessInput(input string) string {
	// Don't add password inputs to history
	for _, pattern := range pf.patterns {
		if pattern.MatchString(input) {
			return "" // Don't save to history
		}
	}
	return input
}

func (pf *PasswordFilter) ProcessOutput(output string) string {
	return output // Don't modify output
}

func (pf *PasswordFilter) ProcessPrompt(prompt string) string {
	return prompt // Don't modify prompt
}

// Utility functions for rlwrap-like behavior

// SetIgnoreCase sets case sensitivity for completions and search
func (e *Editor) SetIgnoreCase(ignore bool) {
	e.ignoreCase = ignore
}

// SetWordBreakChars sets the characters that break words
func (e *Editor) SetWordBreakChars(chars string) {
	e.wordBreakChars = chars
}

// SetEditMode sets the editing mode (emacs or vi)
func (e *Editor) SetEditMode(mode EditMode) {
	e.editMode = mode
}

// SetViMode enables vi editing mode
func (e *Editor) SetViMode() {
	e.editMode = ViInsertMode
}

// SetEmacsMode enables emacs editing mode (default)
func (e *Editor) SetEmacsMode() {
	e.editMode = EmacsMode
}

// SetSyntaxHighlighter sets a custom syntax highlighter function
func (e *Editor) SetSyntaxHighlighter(fn SyntaxHighlighter) {
	e.syntaxHighlighter = fn
}

// SetHintFunction sets a function that provides hints while typing
func (e *Editor) SetHintFunction(fn func(string) string) {
	e.hintFn = fn
}

// SetValidator sets a function that validates input before accepting
func (e *Editor) SetValidator(fn func(string) bool) {
	e.validatorFn = fn
}

// EnableAutoSuggestion enables fish-like auto-suggestions from history
func (e *Editor) EnableAutoSuggestion(enabled bool) {
	e.autoSuggestion = enabled
}

// EnableBracketMatching enables bracket matching highlighting
func (e *Editor) EnableBracketMatching(enabled bool) {
	e.bracketMatching = enabled
}

// EnableMultiLine enables multi-line editing
func (e *Editor) EnableMultiLine(enabled bool) {
	e.multiLine = enabled
}

// AddAlias adds a command alias
func (e *Editor) AddAlias(alias, command string) {
	e.aliases[alias] = command
}

// RemoveAlias removes a command alias
func (e *Editor) RemoveAlias(alias string) {
	delete(e.aliases, alias)
}

// GetAliases returns all defined aliases
func (e *Editor) GetAliases() map[string]string {
	result := make(map[string]string)
	for k, v := range e.aliases {
		result[k] = v
	}
	return result
}

// saveUndo saves current state to undo stack
func (e *Editor) saveUndo() {
	state := undoState{
		line:      make([]rune, len(e.currentLine)),
		cursorPos: e.cursorPos,
	}
	copy(state.line, e.currentLine)
	e.undoStack = append(e.undoStack, state)
	// Clear redo stack on new change
	e.redoStack = make([]undoState, 0)
	// Limit undo stack size
	if len(e.undoStack) > 100 {
		e.undoStack = e.undoStack[1:]
	}
}

// Undo reverts to previous state
func (e *Editor) Undo() {
	if len(e.undoStack) == 0 {
		return
	}
	// Save current state to redo
	redoState := undoState{
		line:      make([]rune, len(e.currentLine)),
		cursorPos: e.cursorPos,
	}
	copy(redoState.line, e.currentLine)
	e.redoStack = append(e.redoStack, redoState)

	// Restore from undo stack
	state := e.undoStack[len(e.undoStack)-1]
	e.undoStack = e.undoStack[:len(e.undoStack)-1]
	e.currentLine = state.line
	e.cursorPos = state.cursorPos
	e.refreshLine()
}

// Redo reapplies undone change
func (e *Editor) Redo() {
	if len(e.redoStack) == 0 {
		return
	}
	// Save current state to undo
	undoState := undoState{
		line:      make([]rune, len(e.currentLine)),
		cursorPos: e.cursorPos,
	}
	copy(undoState.line, e.currentLine)
	e.undoStack = append(e.undoStack, undoState)

	// Restore from redo stack
	state := e.redoStack[len(e.redoStack)-1]
	e.redoStack = e.redoStack[:len(e.redoStack)-1]
	e.currentLine = state.line
	e.cursorPos = state.cursorPos
	e.refreshLine()
}

// AddToKillRing adds text to the kill ring
func (e *Editor) AddToKillRing(text string) {
	if text == "" {
		return
	}
	e.killRing = append(e.killRing, text)
	if len(e.killRing) > 10 {
		e.killRing = e.killRing[1:]
	}
	e.killRingIndex = len(e.killRing) - 1
}

// YankFromKillRing pastes from kill ring
func (e *Editor) YankFromKillRing() {
	if len(e.killRing) == 0 {
		return
	}
	text := e.killRing[e.killRingIndex]
	e.saveUndo()
	e.yankPos = e.cursorPos
	for _, ch := range text {
		e.insertCharNoRefresh(ch)
	}
	e.refreshLine()
}

// YankPop cycles through kill ring
func (e *Editor) YankPop() {
	if len(e.killRing) == 0 || e.yankPos < 0 {
		return
	}
	// Remove previously yanked text
	prevText := e.killRing[e.killRingIndex]
	e.currentLine = append(e.currentLine[:e.yankPos], e.currentLine[e.yankPos+len([]rune(prevText)):]...)
	e.cursorPos = e.yankPos

	// Cycle to previous kill ring entry
	e.killRingIndex--
	if e.killRingIndex < 0 {
		e.killRingIndex = len(e.killRing) - 1
	}

	// Insert new text
	text := e.killRing[e.killRingIndex]
	for _, ch := range text {
		e.insertCharNoRefresh(ch)
	}
	e.refreshLine()
}

// insertCharNoRefresh inserts without refreshing (for batch operations)
func (e *Editor) insertCharNoRefresh(ch rune) {
	if e.cursorPos == len(e.currentLine) {
		e.currentLine = append(e.currentLine, ch)
	} else {
		e.currentLine = append(e.currentLine[:e.cursorPos+1], e.currentLine[e.cursorPos:]...)
		e.currentLine[e.cursorPos] = ch
	}
	e.cursorPos++
}

// SetMark sets the mark for selection
func (e *Editor) SetMark() {
	e.mark = e.cursorPos
}

// GetSelection returns selected text between mark and cursor
func (e *Editor) GetSelection() string {
	if e.mark < 0 {
		return ""
	}
	start, end := e.mark, e.cursorPos
	if start > end {
		start, end = end, start
	}
	if end > len(e.currentLine) {
		end = len(e.currentLine)
	}
	return string(e.currentLine[start:end])
}

// KillRegion cuts selected text to kill ring
func (e *Editor) KillRegion() {
	if e.mark < 0 {
		return
	}
	selection := e.GetSelection()
	if selection == "" {
		return
	}
	e.AddToKillRing(selection)
	e.saveUndo()

	start, end := e.mark, e.cursorPos
	if start > end {
		start, end = end, start
	}
	e.currentLine = append(e.currentLine[:start], e.currentLine[end:]...)
	e.cursorPos = start
	e.mark = -1
	e.refreshLine()
}

// CopyRegion copies selected text to kill ring
func (e *Editor) CopyRegion() {
	selection := e.GetSelection()
	if selection != "" {
		e.AddToKillRing(selection)
	}
	e.mark = -1
}

// TransposeChars swaps character before cursor with character at cursor
func (e *Editor) TransposeChars() {
	if e.cursorPos < 1 || len(e.currentLine) < 2 {
		return
	}
	e.saveUndo()
	pos := e.cursorPos
	if pos >= len(e.currentLine) {
		pos = len(e.currentLine) - 1
	}
	e.currentLine[pos-1], e.currentLine[pos] = e.currentLine[pos], e.currentLine[pos-1]
	if e.cursorPos < len(e.currentLine) {
		e.cursorPos++
	}
	e.refreshLine()
}

// TransposeWords swaps word before cursor with word after cursor
func (e *Editor) TransposeWords() {
	// Find word boundaries
	line := string(e.currentLine)
	words := strings.Fields(line)
	if len(words) < 2 {
		return
	}
	e.saveUndo()
	// Simple implementation: swap last two words
	words[len(words)-2], words[len(words)-1] = words[len(words)-1], words[len(words)-2]
	e.currentLine = []rune(strings.Join(words, " "))
	e.cursorPos = len(e.currentLine)
	e.refreshLine()
}

// UppercaseWord converts word to uppercase
func (e *Editor) UppercaseWord() {
	e.saveUndo()
	start := e.cursorPos
	// Find end of word
	for e.cursorPos < len(e.currentLine) && !strings.ContainsRune(e.wordBreakChars, e.currentLine[e.cursorPos]) {
		e.currentLine[e.cursorPos] = unicode.ToUpper(e.currentLine[e.cursorPos])
		e.cursorPos++
	}
	if start != e.cursorPos {
		e.refreshLine()
	}
}

// LowercaseWord converts word to lowercase
func (e *Editor) LowercaseWord() {
	e.saveUndo()
	start := e.cursorPos
	for e.cursorPos < len(e.currentLine) && !strings.ContainsRune(e.wordBreakChars, e.currentLine[e.cursorPos]) {
		e.currentLine[e.cursorPos] = unicode.ToLower(e.currentLine[e.cursorPos])
		e.cursorPos++
	}
	if start != e.cursorPos {
		e.refreshLine()
	}
}

// CapitalizeWord capitalizes word
func (e *Editor) CapitalizeWord() {
	e.saveUndo()
	// Skip whitespace
	for e.cursorPos < len(e.currentLine) && strings.ContainsRune(e.wordBreakChars, e.currentLine[e.cursorPos]) {
		e.cursorPos++
	}
	// Capitalize first char
	if e.cursorPos < len(e.currentLine) {
		e.currentLine[e.cursorPos] = unicode.ToUpper(e.currentLine[e.cursorPos])
		e.cursorPos++
	}
	// Lowercase rest
	for e.cursorPos < len(e.currentLine) && !strings.ContainsRune(e.wordBreakChars, e.currentLine[e.cursorPos]) {
		e.currentLine[e.cursorPos] = unicode.ToLower(e.currentLine[e.cursorPos])
		e.cursorPos++
	}
	e.refreshLine()
}

// StartMacro starts recording a keyboard macro
func (e *Editor) StartMacro(key rune) {
	e.recordingMacro = true
	e.macroKey = key
	e.currentMacro = make([]rune, 0)
}

// EndMacro stops recording and saves the macro
func (e *Editor) EndMacro() {
	if !e.recordingMacro {
		return
	}
	e.recordingMacro = false
	e.macros[e.macroKey] = string(e.currentMacro)
}

// PlayMacro plays a recorded macro
func (e *Editor) PlayMacro(key rune) {
	macro, ok := e.macros[key]
	if !ok {
		return
	}
	for _, ch := range macro {
		e.insertChar(ch)
	}
}

// getAutoSuggestion returns auto-suggestion from history
func (e *Editor) getAutoSuggestion() string {
	if !e.autoSuggestion || len(e.currentLine) == 0 {
		return ""
	}
	prefix := string(e.currentLine)
	// Search history for matching prefix
	for i := len(e.history) - 1; i >= 0; i-- {
		if strings.HasPrefix(e.history[i], prefix) && e.history[i] != prefix {
			return e.history[i][len(prefix):]
		}
	}
	return ""
}

// AcceptAutoSuggestion accepts the current auto-suggestion
func (e *Editor) AcceptAutoSuggestion() {
	suggestion := e.getAutoSuggestion()
	if suggestion == "" {
		return
	}
	e.saveUndo()
	for _, ch := range suggestion {
		e.insertCharNoRefresh(ch)
	}
	e.refreshLine()
}

// AcceptAutoSuggestionWord accepts one word from auto-suggestion
func (e *Editor) AcceptAutoSuggestionWord() {
	suggestion := e.getAutoSuggestion()
	if suggestion == "" {
		return
	}
	e.saveUndo()
	// Find first word boundary
	for i, ch := range suggestion {
		if strings.ContainsRune(e.wordBreakChars, ch) {
			if i > 0 {
				for _, c := range suggestion[:i] {
					e.insertCharNoRefresh(c)
				}
				e.refreshLine()
			}
			return
		}
		e.insertCharNoRefresh(ch)
	}
	e.refreshLine()
}

// highlightBrackets returns line with bracket highlighting
func (e *Editor) highlightBrackets(line string) string {
	if !e.bracketMatching {
		return line
	}
	// Find matching brackets
	brackets := map[rune]rune{'(': ')', '[': ']', '{': '}'}
	closeBrackets := map[rune]rune{')': '(', ']': '[', '}': '{'}

	runes := []rune(line)
	if e.cursorPos >= len(runes) {
		return line
	}

	ch := runes[e.cursorPos]
	var matchPos int = -1

	if close, ok := brackets[ch]; ok {
		// Find closing bracket
		depth := 1
		for i := e.cursorPos + 1; i < len(runes); i++ {
			if runes[i] == ch {
				depth++
			} else if runes[i] == close {
				depth--
				if depth == 0 {
					matchPos = i
					break
				}
			}
		}
	} else if open, ok := closeBrackets[ch]; ok {
		// Find opening bracket
		depth := 1
		for i := e.cursorPos - 1; i >= 0; i-- {
			if runes[i] == ch {
				depth++
			} else if runes[i] == open {
				depth--
				if depth == 0 {
					matchPos = i
					break
				}
			}
		}
	}

	if matchPos >= 0 {
		// Highlight matching bracket
		highlighted := color.New(color.FgCyan, color.Bold).Sprint(string(runes[matchPos]))
		result := string(runes[:matchPos]) + highlighted
		if matchPos+1 < len(runes) {
			result += string(runes[matchPos+1:])
		}
		return result
	}

	return line
}

// expandAlias expands command aliases
func (e *Editor) expandAlias(input string) string {
	words := strings.Fields(input)
	if len(words) == 0 {
		return input
	}
	if expanded, ok := e.aliases[words[0]]; ok {
		words[0] = expanded
		return strings.Join(words, " ")
	}
	return input
}

// GetTerminalSize returns the current terminal size
func GetTerminalSize() (width, height int, err error) {
	fd := int(os.Stdout.Fd())
	width, height, err = term.GetSize(fd)
	return
}

// IsTerminal checks if the given file descriptor is a terminal
func IsTerminal(fd int) bool {
	return term.IsTerminal(fd)
}

// FormatDuration formats a duration for display
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	} else if d < time.Hour {
		return fmt.Sprintf("%.1fm", d.Minutes())
	} else {
		return fmt.Sprintf("%.1fh", d.Hours())
	}
}

// ParsePortRange parses a port range string like "80-443" or "22,80,443"
func ParsePortRange(portRange string) ([]int, error) {
	var ports []int

	// Handle comma-separated ports
	if strings.Contains(portRange, ",") {
		parts := strings.Split(portRange, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if port, err := strconv.Atoi(part); err == nil {
				if port > 0 && port <= 65535 {
					ports = append(ports, port)
				}
			}
		}
		return ports, nil
	}

	// Handle range like "80-443"
	if strings.Contains(portRange, "-") {
		parts := strings.Split(portRange, "-")
		if len(parts) == 2 {
			start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 == nil && err2 == nil && start <= end && start > 0 && end <= 65535 {
				for port := start; port <= end; port++ {
					ports = append(ports, port)
				}
				return ports, nil
			}
		}
	}

	// Handle single port
	if port, err := strconv.Atoi(strings.TrimSpace(portRange)); err == nil {
		if port > 0 && port <= 65535 {
			ports = append(ports, port)
			return ports, nil
		}
	}

	return nil, fmt.Errorf("invalid port range: %s", portRange)
}

// ShellSyntaxHighlighter provides syntax highlighting for shell commands
func ShellSyntaxHighlighter(input string) string {
	if input == "" {
		return input
	}

	words := strings.Fields(input)
	if len(words) == 0 {
		return input
	}

	// Common shell commands to highlight
	builtins := map[string]bool{
		"cd": true, "pwd": true, "echo": true, "export": true, "alias": true,
		"source": true, "exit": true, "return": true, "break": true, "continue": true,
		"if": true, "then": true, "else": true, "elif": true, "fi": true,
		"for": true, "while": true, "do": true, "done": true, "case": true, "esac": true,
		"function": true, "local": true, "declare": true, "readonly": true,
		"set": true, "unset": true, "shift": true, "trap": true,
	}

	commands := map[string]bool{
		"ls": true, "cat": true, "grep": true, "find": true, "sed": true, "awk": true,
		"rm": true, "cp": true, "mv": true, "mkdir": true, "rmdir": true, "touch": true,
		"chmod": true, "chown": true, "ps": true, "kill": true, "top": true,
		"ssh": true, "scp": true, "curl": true, "wget": true, "ping": true,
		"git": true, "docker": true, "kubectl": true, "make": true, "go": true,
		"python": true, "node": true, "npm": true, "pip": true, "ruby": true,
		"sudo": true, "su": true, "apt": true, "yum": true, "brew": true,
		"tar": true, "gzip": true, "unzip": true, "zip": true,
		"head": true, "tail": true, "less": true, "more": true, "wc": true,
		"sort": true, "uniq": true, "cut": true, "tr": true, "xargs": true,
		"man": true, "which": true, "whereis": true, "type": true,
		"nc": true, "netcat": true, "nmap": true, "tcpdump": true, "wireshark": true,
	}

	var result strings.Builder
	cmdColor := color.New(color.FgGreen, color.Bold)
	builtinColor := color.New(color.FgCyan, color.Bold)
	stringColor := color.New(color.FgYellow)
	flagColor := color.New(color.FgMagenta)
	varColor := color.New(color.FgBlue)
	pipeColor := color.New(color.FgRed, color.Bold)

	inString := false
	stringChar := rune(0)
	isFirstWord := true

	for i := 0; i < len(input); i++ {
		ch := rune(input[i])

		// Handle strings
		if ch == '"' || ch == '\'' {
			if !inString {
				inString = true
				stringChar = ch
				result.WriteString(stringColor.Sprint(string(ch)))
				continue
			} else if ch == stringChar {
				inString = false
				result.WriteString(stringColor.Sprint(string(ch)))
				continue
			}
		}

		if inString {
			result.WriteString(stringColor.Sprint(string(ch)))
			continue
		}

		// Handle variables
		if ch == '$' {
			varStart := i
			i++
			if i < len(input) && input[i] == '{' {
				// ${VAR}
				for i < len(input) && input[i] != '}' {
					i++
				}
				if i < len(input) {
					i++
				}
			} else {
				// $VAR
				for i < len(input) && (unicode.IsLetter(rune(input[i])) || unicode.IsDigit(rune(input[i])) || input[i] == '_') {
					i++
				}
			}
			result.WriteString(varColor.Sprint(input[varStart:i]))
			i--
			continue
		}

		// Handle pipes and redirects
		if ch == '|' || ch == '>' || ch == '<' || ch == '&' {
			result.WriteString(pipeColor.Sprint(string(ch)))
			isFirstWord = true
			continue
		}

		// Handle flags
		if ch == '-' && i+1 < len(input) && !unicode.IsSpace(rune(input[i+1])) {
			flagStart := i
			for i < len(input) && !unicode.IsSpace(rune(input[i])) {
				i++
			}
			result.WriteString(flagColor.Sprint(input[flagStart:i]))
			i--
			continue
		}

		// Handle words
		if !unicode.IsSpace(ch) {
			wordStart := i
			for i < len(input) && !unicode.IsSpace(rune(input[i])) && input[i] != '|' && input[i] != '>' && input[i] != '<' {
				i++
			}
			word := input[wordStart:i]

			if isFirstWord {
				if builtins[word] {
					result.WriteString(builtinColor.Sprint(word))
				} else if commands[word] {
					result.WriteString(cmdColor.Sprint(word))
				} else {
					result.WriteString(word)
				}
				isFirstWord = false
			} else {
				result.WriteString(word)
			}
			i--
			continue
		}

		// Handle whitespace
		if unicode.IsSpace(ch) {
			result.WriteRune(ch)
		}
	}

	return result.String()
}

// ViModeIndicator returns a string indicating current vi mode
func (e *Editor) ViModeIndicator() string {
	switch e.editMode {
	case ViInsertMode:
		return color.New(color.FgGreen).Sprint("[I]")
	case ViCommandMode:
		return color.New(color.FgYellow).Sprint("[N]")
	default:
		return ""
	}
}

// handleViCommand handles vi command mode keys
func (e *Editor) handleViCommand(ch byte) bool {
	switch ch {
	case 'i': // Insert mode
		e.editMode = ViInsertMode
		return true
	case 'a': // Append
		e.editMode = ViInsertMode
		if e.cursorPos < len(e.currentLine) {
			e.cursorPos++
		}
		return true
	case 'A': // Append at end
		e.editMode = ViInsertMode
		e.cursorPos = len(e.currentLine)
		return true
	case 'I': // Insert at beginning
		e.editMode = ViInsertMode
		e.cursorPos = 0
		return true
	case 'h': // Left
		e.cursorLeft()
		return true
	case 'l': // Right
		e.cursorRight()
		return true
	case 'j': // Down (history)
		e.historyDown()
		return true
	case 'k': // Up (history)
		e.historyUp()
		return true
	case '0': // Beginning of line
		e.cursorPos = 0
		e.refreshLine()
		return true
	case '$': // End of line
		e.cursorPos = len(e.currentLine)
		e.refreshLine()
		return true
	case 'w': // Word forward
		e.wordForward()
		return true
	case 'b': // Word backward
		e.wordBackward()
		return true
	case 'x': // Delete char
		e.deleteChar()
		return true
	case 'X': // Delete char before
		e.backspace()
		return true
	case 'd':
		// Wait for next char
		ch2, err := e.readChar()
		if err != nil {
			return true
		}
		switch ch2 {
		case 'd': // dd - delete line
			e.saveUndo()
			e.AddToKillRing(string(e.currentLine))
			e.currentLine = make([]rune, 0)
			e.cursorPos = 0
			e.refreshLine()
		case 'w': // dw - delete word
			e.killWordForward()
		case '$': // d$ - delete to end
			e.saveUndo()
			e.AddToKillRing(string(e.currentLine[e.cursorPos:]))
			e.currentLine = e.currentLine[:e.cursorPos]
			e.refreshLine()
		case '0': // d0 - delete to beginning
			e.saveUndo()
			e.AddToKillRing(string(e.currentLine[:e.cursorPos]))
			e.currentLine = e.currentLine[e.cursorPos:]
			e.cursorPos = 0
			e.refreshLine()
		}
		return true
	case 'c':
		// Wait for next char
		ch2, err := e.readChar()
		if err != nil {
			return true
		}
		switch ch2 {
		case 'c': // cc - change line
			e.saveUndo()
			e.currentLine = make([]rune, 0)
			e.cursorPos = 0
			e.editMode = ViInsertMode
			e.refreshLine()
		case 'w': // cw - change word
			e.killWordForward()
			e.editMode = ViInsertMode
		}
		return true
	case 'y':
		// Wait for next char
		ch2, err := e.readChar()
		if err != nil {
			return true
		}
		switch ch2 {
		case 'y': // yy - yank line
			e.AddToKillRing(string(e.currentLine))
		case 'w': // yw - yank word
			start := e.cursorPos
			e.wordForward()
			e.AddToKillRing(string(e.currentLine[start:e.cursorPos]))
			e.cursorPos = start
		}
		return true
	case 'p': // Paste after
		e.YankFromKillRing()
		return true
	case 'P': // Paste before
		if e.cursorPos > 0 {
			e.cursorPos--
		}
		e.YankFromKillRing()
		return true
	case 'u': // Undo
		e.Undo()
		return true
	case 18: // Ctrl+R - redo
		e.Redo()
		return true
	case '/': // Search forward
		e.reverseSearch()
		return true
	case 'n': // Next search result
		// Not implemented
		return true
	case 'N': // Previous search result
		// Not implemented
		return true
	}
	return false
}

// IncrementalSearch performs incremental search through history
func (e *Editor) IncrementalSearch(forward bool) {
	fmt.Print("\n")
	if forward {
		fmt.Print("(i-search): ")
	} else {
		fmt.Print("(reverse-i-search): ")
	}

	searchTerm := ""
	matchIndex := -1
	render := func() {
		fmt.Print("\r\033[K")
		if forward {
			fmt.Printf("(i-search): %s", searchTerm)
		} else {
			fmt.Printf("(reverse-i-search): %s", searchTerm)
		}
		if matchIndex >= 0 {
			fmt.Printf(" -> %s", e.history[matchIndex])
		}
	}

	for {
		ch, err := e.readChar()
		if err != nil {
			break
		}

		switch ch {
		case 13: // Enter
			if matchIndex >= 0 {
				e.currentLine = []rune(e.history[matchIndex])
				e.cursorPos = len(e.currentLine)
			}
			fmt.Print("\n")
			e.refreshLine()
			return

		case 27: // Escape
			fmt.Print("\n")
			e.refreshLine()
			return

		case 18: // Ctrl+R - search backward
			if matchIndex > 0 {
				for i := matchIndex - 1; i >= 0; i-- {
					if strings.Contains(e.history[i], searchTerm) {
						matchIndex = i
						break
					}
				}
			}
			render()
			continue

		case 19: // Ctrl+S - search forward
			if matchIndex < len(e.history)-1 {
				for i := matchIndex + 1; i < len(e.history); i++ {
					if strings.Contains(e.history[i], searchTerm) {
						matchIndex = i
						break
					}
				}
			}
			render()
			continue

		case 127, 8: // Backspace
			if len(searchTerm) > 0 {
				searchTerm = searchTerm[:len(searchTerm)-1]
			}

		default:
			if unicode.IsPrint(rune(ch)) {
				searchTerm += string(rune(ch))
			}
		}

		// Find match
		matchIndex = -1
		if forward {
			for i := 0; i < len(e.history); i++ {
				if strings.Contains(e.history[i], searchTerm) {
					matchIndex = i
					break
				}
			}
		} else {
			for i := len(e.history) - 1; i >= 0; i-- {
				if strings.Contains(e.history[i], searchTerm) {
					matchIndex = i
					break
				}
			}
		}

		render()
	}
}
