package cmdutil

import (
	"fmt"
	"golang.org/x/term"
	"syscall"
)

func EnterPassword(title string) (string, error) {
	fmt.Print(title)
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}
	fmt.Printf("\n")

	password := string(bytePassword)
	return password, nil
}
