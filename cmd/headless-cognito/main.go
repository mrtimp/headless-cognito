package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	flags "github.com/jessevdk/go-flags"
	"github.com/mrtimp/headless-cognito/internal/auth"
	"github.com/sirupsen/logrus"
)

type commonOptions struct {
	Endpoint         string `long:"endpoint" description:"Protected application endpoint" required:"true"`
	Username         string `long:"username" description:"Cognito username" required:"true"`
	Password         string `long:"password" description:"Cognito password"`
	PasswordStdin    bool   `long:"password-stdin" description:"Read the Cognito password from stdin"`
	IdentityProvider string `long:"identity-provider" description:"Cognito identity provider" default:"COGNITO"`
	MaxRedirects     int    `long:"max-redirects" description:"Maximum number of redirects" default:"20"`
	Verbose          bool   `long:"verbose" description:"Enable debug logging"`
}

type authOptions struct {
	commonOptions
	OutputFile   string `long:"output-file" description:"Write the result to a file instead of stdout"`
	OutputFormat string `long:"output-format" description:"Output format: json or github-env" default:"json"`
}

type exportEnvOptions struct {
	InputFile string `long:"input-file" description:"Authentication JSON file" required:"true"`
}

func main() {
	var authOptions authOptions
	var exportEnvOptions exportEnvOptions

	parser := flags.NewParser(nil, flags.Default)
	if _, err := parser.Command.AddCommand("auth", "Authenticate and output cookies", "Authenticate with Cognito and output the resulting cookies.", &authOptions); err != nil {
		panic(err)
	}
	if _, err := parser.Command.AddCommand("export-env", "Export authentication environment variables", "Read authentication JSON and write the cookie variables to an environment file.", &exportEnvOptions); err != nil {
		panic(err)
	}
	if _, err := parser.Parse(); err != nil {
		os.Exit(2)
	}

	activeCommand := parser.Command.Active
	if activeCommand == nil {
		parser.WriteHelp(os.Stderr)
		os.Exit(2)
	}

	if activeCommand.Name == "export-env" {
		githubEnv := os.Getenv("GITHUB_ENV")
		if githubEnv == "" {
			fmt.Fprintln(os.Stderr, "GITHUB_ENV is not set; export-env must run in a GitHub Actions workflow")
			os.Exit(2)
		}

		result, err := readResult(exportEnvOptions.InputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			os.Exit(2)
		}

		if err := writeResult(result, githubEnv, "github-env"); err != nil {
			fmt.Fprintf(os.Stderr, "error: write environment file: %s\n", err)
			os.Exit(1)
		}

		return
	}

	run(authOptions.commonOptions, authOptions.OutputFile, authOptions.OutputFormat)
}

func run(options commonOptions, outputFile string, outputFormat string) {
	log := logrus.New()
	log.SetOutput(os.Stderr)
	if options.Verbose {
		log.SetLevel(logrus.DebugLevel)
	}

	password, err := passwordFromOptions(options)
	if err != nil {
		log.WithError(err).Error("read password")
		os.Exit(2)
	}

	client, err := auth.NewClient(auth.Config{
		Endpoint:         options.Endpoint,
		Username:         options.Username,
		Password:         password,
		IdentityProvider: options.IdentityProvider,
		Logger:           verboseLogger(log, options.Verbose),
		MaxRedirects:     options.MaxRedirects,
	})
	if err != nil {
		log.WithError(err).Error("configure authentication client")
		os.Exit(2)
	}

	log.WithFields(logrus.Fields{
		"endpoint":          options.Endpoint,
		"identity_provider": options.IdentityProvider,
	}).Info("starting Cognito authentication flow")

	result, err := client.Authenticate(context.Background())
	if err != nil {
		log.WithError(err).Error("authenticate with Cognito")
		os.Exit(1)
	}

	log.WithFields(logrus.Fields{
		"endpoint":          options.Endpoint,
		"identity_provider": options.IdentityProvider,
	}).Info("Cognito authentication flow completed")

	if err := writeResult(result, outputFile, outputFormat); err != nil {
		log.WithError(err).Error("write authentication result")

		os.Exit(1)
	}
}

func writeResult(result auth.Result, outputFile string, outputFormat string) error {
	format := strings.ToLower(outputFormat)
	if format != "json" && format != "github-env" {
		return fmt.Errorf("unsupported output format %q; use json or github-env", outputFormat)
	}

	if format == "github-env" && outputFile == "" {
		return fmt.Errorf("--output-file is required with --output-format github-env")
	}

	if err := validateResult(result); err != nil {
		return err
	}

	output := io.Writer(os.Stdout)
	var file *os.File
	if outputFile != "" {
		var err error
		file, err = os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("open output file: %w", err)
		}
		defer file.Close()
		output = file
	}

	if format == "json" {
		if err := json.NewEncoder(output).Encode(result); err != nil {
			return err
		}
		return nil
	}

	values := map[string]string{
		"AWSALB_AUTH_NONCE":            result.Cookies["AWSALBAuthNonce"],
		"AWSELB_AUTH_SESSION_COOKIE_0": result.Cookies["AWSELBAuthSessionCookie-0"],
		"AWSELB_AUTH_SESSION_COOKIE_1": result.Cookies["AWSELBAuthSessionCookie-1"],
	}

	for name, value := range values {
		if _, err := fmt.Fprintf(output, "%s=%s\n", name, value); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "::add-mask::%s\n", value)
	}

	return nil
}

func readResult(inputFile string) (auth.Result, error) {
	file, err := os.Open(inputFile)
	if err != nil {
		if os.IsNotExist(err) {
			return auth.Result{}, fmt.Errorf("authentication JSON file %q does not exist", inputFile)
		}

		return auth.Result{}, fmt.Errorf("open authentication JSON file: %w", err)
	}

	defer file.Close()

	var result auth.Result
	if err := json.NewDecoder(file).Decode(&result); err != nil {
		return auth.Result{}, fmt.Errorf("parse authentication JSON file: %w", err)
	}

	if err := validateResult(result); err != nil {
		return auth.Result{}, fmt.Errorf("invalid authentication JSON file: %w", err)
	}

	return result, nil
}

func validateResult(result auth.Result) error {
	for _, name := range []string{
		"AWSALBAuthNonce",
		"AWSELBAuthSessionCookie-0",
		"AWSELBAuthSessionCookie-1",
	} {
		if strings.TrimSpace(result.Cookies[name]) == "" {
			return fmt.Errorf("authentication JSON is missing expected cookie %q", name)
		}
	}

	return nil
}

func verboseLogger(log *logrus.Logger, verbose bool) logrus.FieldLogger {
	if verbose {
		return log
	}

	return nil
}

func passwordFromOptions(options commonOptions) (string, error) {
	if options.Password != "" && options.PasswordStdin {
		return "", fmt.Errorf("use either --password or --password-stdin, not both")
	}

	if options.PasswordStdin {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", err
		}

		password := strings.TrimSuffix(string(data), "\n")
		password = strings.TrimSuffix(password, "\r")
		if password == "" {
			return "", fmt.Errorf("stdin password is empty")
		}

		return password, nil
	}

	if options.Password == "" {
		return "", fmt.Errorf("one of --password or --password-stdin is required")
	}

	return options.Password, nil
}
