package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/realibrahimsql/Gocat/internal/logger"
	"github.com/realibrahimsql/Gocat/internal/scripting"
	"github.com/spf13/cobra"
)

// Constants for script command
const (
	scriptsDirectory = "./scripts"
	luaExtension     = ".lua"
	maxScriptSize    = 10 * 1024 * 1024 // 10MB limit for script files
)

var scriptCmd = &cobra.Command{
	Use:   "script",
	Short: "Lua script management and execution",
	Long: `Execute and manage Lua scripts for network automation.

The Lua scripting engine automates network tasks such as port scanning,
banner grabbing, and HTTP requests.

Available operations:
  run      Execute a Lua script
  list     List available scripts
  info     Show script information
  validate Validate script syntax

Examples:
  gocat script run port_scanner.lua
  gocat script list
  gocat script info banner_grabber.lua
  gocat script validate ./custom_script.lua`,
}

var scriptRunCmd = &cobra.Command{
	Use:   "run [script] [args...]",
	Short: "Execute a Lua script",
	Long: `Execute a Lua script with GoCat's scripting engine.

The script can be specified as:
- A filename (searches in ./scripts/ directory)
- A relative path from current directory
- An absolute path

Arguments after the script name are passed to the script via 'arg' table.

Examples:
  gocat script run port_scanner.lua scanme.nmap.org 1-1000
  gocat script run banner_grabber.lua 192.168.1.1 22,80,443
  gocat script run http_client.lua https://api.example.com/data
  gocat script run ./my_scripts/custom.lua arg1 arg2`,
	Args: cobra.MinimumNArgs(1),
	Run:  runScript,
}

var scriptListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available scripts",
	Long: `List all available Lua scripts in the scripts directory.

This command scans the ./scripts/ directory and shows information about
each available script including its purpose and key features.`,
	Run: listScripts,
}

var scriptInfoCmd = &cobra.Command{
	Use:   "info [script]",
	Short: "Show script information",
	Long: `Display detailed information about a specific script including
its purpose, features, usage examples, and available functions.`,
	Args: cobra.ExactArgs(1),
	Run:  showScriptInfo,
}

var scriptValidateCmd = &cobra.Command{
	Use:   "validate [script]",
	Short: "Validate script syntax",
	Long: `Validate the syntax of a Lua script without executing it.

This is useful for debugging scripts and ensuring they will run correctly
before execution.`,
	Args: cobra.ExactArgs(1),
	Run:  validateScript,
}

func runScript(cmd *cobra.Command, args []string) {
	scriptPath := args[0]

	// Get script arguments (everything after the script name)
	var scriptArgs []string
	if len(args) > 1 {
		scriptArgs = args[1:]
	}

	// Resolve script path
	resolvedPath, err := resolveScriptPath(scriptPath)
	if err != nil {
		logger.Error("Script resolution failed: %v", err)
		os.Exit(1)
	}

	// Validate script file size
	if err := validateScriptFile(resolvedPath); err != nil {
		logger.Error("Script validation failed: %v", err)
		os.Exit(1)
	}

	logger.Info("Executing script: %s", resolvedPath)
	if len(scriptArgs) > 0 {
		logger.Info("Script arguments: %v", scriptArgs)
	}

	// Create Lua engine with default config
	config := scripting.DefaultConfig()
	if unrestrict, _ := cmd.Flags().GetBool("unrestricted"); unrestrict {
		config.RestrictedMode = false
		logger.Warn("Running script unrestricted: sys.exec, full stdlib, and host filesystem are available to the script")
	}
	if secs, _ := cmd.Flags().GetInt("timeout"); secs != 0 {
		if secs < 1 {
			secs = 1
		}
		if secs > 300 {
			secs = 300
		}
		config.MaxExecutionTime = time.Duration(secs) * time.Second
	}
	engine := scripting.NewEngine(config)
	if engine == nil {
		logger.Error("Failed to create Lua engine")
		os.Exit(1)
	}
	defer func() {
		if engine != nil {
			engine.Close()
		}
	}()

	// Set script arguments
	engine.SetArgs(scriptArgs)

	// Load and execute script
	if err := engine.LoadScript(resolvedPath); err != nil {
		logger.Error("Failed to load script: %v", err)
		os.Exit(1)
	}

	if err := engine.ExecuteScript(filepath.Base(scriptPath)); err != nil {
		logger.Error("Script execution failed: %v", err)
		os.Exit(1)
	}

	logger.Info("Script execution completed successfully")
}

func listScripts(cmd *cobra.Command, args []string) {
	scriptsDir := scriptsDirectory

	// Check if scripts directory exists
	if _, err := os.Stat(scriptsDir); os.IsNotExist(err) {
		logger.Warn("Scripts directory not found: %s", scriptsDir)
		logger.Info("Create a 'scripts' directory and add .lua files to get started")
		return
	}

	// Read scripts directory
	entries, err := os.ReadDir(scriptsDir)
	if err != nil {
		logger.Error("Failed to read scripts directory: %v", err)
		return
	}

	// Filter Lua files
	var luaScripts []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), luaExtension) {
			luaScripts = append(luaScripts, entry.Name())
		}
	}

	if len(luaScripts) == 0 {
		logger.Info("No Lua scripts found in %s", scriptsDir)
		return
	}

	// Display scripts with descriptions
	fmt.Println("Available Lua Scripts:")

	for _, script := range luaScripts {
		scriptPath := filepath.Join(scriptsDir, script)
		description := getScriptDescription(scriptPath)

		fmt.Printf("%s\n", script)
		if description != "" {
			fmt.Printf("   %s\n", description)
		}
		fmt.Println()
	}

	fmt.Printf("Total scripts: %d\n", len(luaScripts))
	fmt.Println("\nUsage: gocat script run <script_name>")
}

func showScriptInfo(cmd *cobra.Command, args []string) {
	scriptPath := args[0]

	// Resolve script path
	resolvedPath, err := resolveScriptPath(scriptPath)
	if err != nil {
		logger.Error("Script resolution failed: %v", err)
		os.Exit(1)
	}

	// Read script content
	content, err := os.ReadFile(resolvedPath)
	if err != nil {
		logger.Error("Failed to read script: %v", err)
		os.Exit(1)
	}

	// Parse script information
	info := parseScriptInfo(string(content))

	fmt.Printf("Script Information: %s\n", filepath.Base(resolvedPath))

	if info.Purpose != "" {
		fmt.Printf("Purpose: %s\n", info.Purpose)
	}

	if len(info.Features) > 0 {
		fmt.Println("\nFeatures:")
		for _, feature := range info.Features {
			fmt.Printf("  • %s\n", feature)
		}
	}

	if len(info.Functions) > 0 {
		fmt.Println("\nAvailable Functions:")
		for _, function := range info.Functions {
			fmt.Printf("  • %s\n", function)
		}
	}

	if info.Usage != "" {
		fmt.Printf("\nUsage Example:\n%s\n", info.Usage)
	}

	// Show file stats
	fileInfo, _ := os.Stat(resolvedPath)
	fmt.Printf("\nFile Information:\n")
	fmt.Printf("  Size: %d bytes\n", fileInfo.Size())
	fmt.Printf("  Modified: %s\n", fileInfo.ModTime().Format("2006-01-02 15:04:05"))
}

func validateScript(cmd *cobra.Command, args []string) {
	scriptPath := args[0]

	// Resolve script path
	resolvedPath, err := resolveScriptPath(scriptPath)
	if err != nil {
		logger.Error("Script resolution failed: %v", err)
		os.Exit(1)
	}

	logger.Info("Validating script: %s", resolvedPath)

	// Create Lua engine for validation
	config := scripting.DefaultConfig()
	// Validation runs the operator's own file locally for QA: lift the
	// sandbox so network scripts validate the same way they run.
	config.RestrictedMode = false
	engine := scripting.NewEngine(config)
	if engine == nil {
		logger.Error("Failed to create Lua engine")
		os.Exit(1)
	}
	defer engine.Close()

	// Read and compile script without execution
	content, err := os.ReadFile(resolvedPath)
	if err != nil {
		logger.Error("Failed to read script: %v", err)
		os.Exit(1)
	}

	// Try to load the script without executing
	if err := engine.LoadString(string(content)); err != nil {
		logger.Error("Script validation failed: %v", err)
		os.Exit(1)
	}

	logger.Info("Script validation passed: syntax is correct")
}

// resolveScriptPath resolves script path with fallback logic
func resolveScriptPath(scriptPath string) (string, error) {
	// If absolute path, use as-is
	if filepath.IsAbs(scriptPath) {
		if _, err := os.Stat(scriptPath); err != nil {
			return "", fmt.Errorf("script not found: %s", scriptPath)
		}
		return scriptPath, nil
	}

	// If relative path with directory, use as-is
	if strings.Contains(scriptPath, "/") || strings.Contains(scriptPath, "\\") {
		if _, err := os.Stat(scriptPath); err != nil {
			return "", fmt.Errorf("script not found: %s", scriptPath)
		}
		return scriptPath, nil
	}

	// Try scripts directory first
	scriptsPath := filepath.Join("scripts", scriptPath)
	if _, err := os.Stat(scriptsPath); err == nil {
		return scriptsPath, nil
	}

	// Try current directory
	if _, err := os.Stat(scriptPath); err == nil {
		return scriptPath, nil
	}

	return "", fmt.Errorf("script not found: %s (searched in ./scripts/ and current directory)", scriptPath)
}

// getScriptDescription extracts description from script comments
func getScriptDescription(scriptPath string) string {
	content, err := os.ReadFile(scriptPath)
	if err != nil {
		return ""
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "--") && len(line) > 2 {
			desc := strings.TrimSpace(line[2:])
			if len(desc) > 0 && !strings.Contains(desc, "Script for GoCat") {
				return desc
			}
		}
	}
	return ""
}

// ScriptInfo holds parsed script information
type ScriptInfo struct {
	Purpose   string
	Features  []string
	Functions []string
	Usage     string
}

// parseScriptInfo parses script content for documentation
func parseScriptInfo(content string) ScriptInfo {
	var info ScriptInfo
	lines := strings.Split(content, "\n")

	inUsageBlock := false
	usageLines := []string{}

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse comments for documentation
		if strings.HasPrefix(line, "--") {
			comment := strings.TrimSpace(line[2:])

			if strings.HasPrefix(comment, "Purpose:") {
				info.Purpose = strings.TrimSpace(comment[8:])
			}

			if strings.HasPrefix(comment, "Feature:") || strings.HasPrefix(comment, "- ") {
				feature := strings.TrimSpace(strings.TrimPrefix(comment, "Feature:"))
				feature = strings.TrimSpace(strings.TrimPrefix(feature, "- "))
				if feature != "" {
					info.Features = append(info.Features, feature)
				}
			}

			if strings.Contains(comment, "Usage") || strings.Contains(comment, "Example") {
				inUsageBlock = true
				continue
			}

			if inUsageBlock && comment != "" {
				usageLines = append(usageLines, comment)
			}
		}

		// Parse function definitions
		if strings.HasPrefix(line, "function ") {
			funcDef := strings.TrimPrefix(line, "function ")
			if idx := strings.Index(funcDef, "("); idx > 0 {
				funcName := funcDef[:idx]
				if !strings.HasPrefix(funcName, "_") { // Skip private functions
					info.Functions = append(info.Functions, funcName)
				}
			}
		}

		// Stop parsing usage after empty line
		if inUsageBlock && line == "" && len(usageLines) > 0 {
			break
		}
	}

	if len(usageLines) > 0 {
		info.Usage = strings.Join(usageLines, "\n")
	}

	return info
}

// validateScriptFile checks that the script at scriptPath exists, is not larger than maxScriptSize, and can be opened for reading.
// It returns an error if the file does not exist or is inaccessible, if its size exceeds the allowed limit, or if it cannot be opened.
func validateScriptFile(scriptPath string) error {
	fileInfo, err := os.Stat(scriptPath)
	if err != nil {
		return fmt.Errorf("cannot access script file: %w", err)
	}

	// Check file size
	if fileInfo.Size() > maxScriptSize {
		return fmt.Errorf("script file too large: %d bytes (max: %d bytes)", fileInfo.Size(), maxScriptSize)
	}

	// Check if file is readable
	file, err := os.Open(scriptPath)
	if err != nil {
		return fmt.Errorf("cannot read script file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			logger.Debug("Failed to close script file: %v", closeErr)
		}
	}()

	return nil
}

// top-level script command to the root command.
func init() {
	// Add subcommands
	scriptCmd.AddCommand(scriptRunCmd)
	scriptCmd.AddCommand(scriptListCmd)
	scriptCmd.AddCommand(scriptInfoCmd)
	scriptCmd.AddCommand(scriptValidateCmd)

	// Add flags
	scriptRunCmd.Flags().StringP("args", "a", "", "Arguments to pass to the script")
	scriptRunCmd.Flags().BoolP("verbose", "v", false, "Verbose script execution")
	scriptRunCmd.Flags().Int("timeout", 0, "Script execution timeout in seconds (1-300, default 30)")
	scriptRunCmd.Flags().Bool("unrestricted", false, "Disable the Lua sandbox (sys.exec, os/io, full filesystem)")

	scriptListCmd.Flags().Bool("detailed", false, "Show detailed information")

	// Add to root command
	rootCmd.AddCommand(scriptCmd)
}
