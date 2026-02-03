package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"

	client "github.com/gwillem/signal-go"
	"golang.org/x/term"
)

type registerCommand struct {
	Args struct {
		Number string `positional-arg-name:"number" required:"true" description:"Phone number in E.164 format (+31612345678)"`
	} `positional-args:"true" required:"true"`
	Voice bool `long:"voice" description:"Request voice call instead of SMS"`
}

// readLine reads a line from stdin using normal buffered reading.
func readLine() (string, error) {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	if scanner.Scan() {
		return scanner.Text(), nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("no input")
}

// readLineRaw reads a line using raw terminal mode, which handles large pastes better.
// It echoes characters as they're typed/pasted.
func readLineRaw() (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		oldState, err := term.MakeRaw(fd)
		if err != nil {
			return "", fmt.Errorf("make raw: %w", err)
		}
		defer term.Restore(fd, oldState)
	}

	r := bufio.NewReaderSize(os.Stdin, 64*1024)
	var b []byte
	for {
		c, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if c == '\n' || c == '\r' {
			break
		}
		// Echo the character
		os.Stdout.Write([]byte{c})
		b = append(b, c)
	}
	return string(b), nil
}

func (cmd *registerCommand) Execute(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	c := client.NewClient(clientOpts()...)

	transport := "sms"
	if cmd.Voice {
		transport = "voice"
	}

	fmt.Printf("Registering %s as a new Signal account...\n", cmd.Args.Number)
	if cmd.Voice {
		fmt.Println("You will receive a voice call with the verification code.")
	} else {
		fmt.Println("You will receive an SMS with the verification code.")
	}
	fmt.Println()

	getCode := func() (string, error) {
		fmt.Print("Enter verification code: ")
		code, err := readLine()
		if err != nil {
			return "", err
		}
		fmt.Println("Submitting verification code...")
		return strings.TrimSpace(code), nil
	}

	getCaptcha := func() (string, error) {
		fmt.Println()
		fmt.Println("CAPTCHA required!")
		fmt.Println("1. Open this URL in your browser (solve it quickly, tokens expire fast):")
		fmt.Println("   https://signalcaptchas.org/registration/generate.html")
		fmt.Println("2. Solve the CAPTCHA")
		fmt.Println("3. Paste the signalcaptcha://... token and press Enter")
		fmt.Println()
		fmt.Print("Enter CAPTCHA token: ")
		token, err := readLineRaw()
		fmt.Println() // newline after raw mode input
		if err != nil {
			return "", err
		}
		token = strings.TrimSpace(token)
		// Strip the signalcaptcha:// prefix if present.
		token = strings.TrimPrefix(token, "signalcaptcha://")
		fmt.Printf("Submitting CAPTCHA token (%d chars)...\n", len(token))
		return token, nil
	}

	err := c.Register(ctx, cmd.Args.Number, transport, getCode, getCaptcha)
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("Registered successfully!")
	fmt.Printf("Number: %s\n", c.Number())
	fmt.Printf("Device ID: %d (primary)\n", c.DeviceID())

	return nil
}
