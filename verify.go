package main

import (
	"fmt"
	"os"
	"sync"

	gomail "gopkg.in/mail.v2" // "net/smtp"
)

var dialer = gomail.NewDialer("live.smtp.mailtrap.io", 587, "api", os.Getenv("EMAIL_TOKEN"))
var sender gomail.SendCloser
var mu sync.Mutex

func init() {
	s, e := dialer.Dial()
	if e != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to smtp server:\n %v\n", e)
		os.Exit(1)
	}
	sender = s
}

func SendVerificationMessage(email string, code string) error {
	message := gomail.NewMessage()
	message.SetHeader("From", "noreply@demomailtrap.com")
	message.SetHeader("To", email)
	message.SetHeader("Subject", "Rafiq Verification Message")
	message.SetBody("text/plain", "Your verification code is: "+code)

	mu.Lock()
	defer mu.Unlock()
	return gomail.Send(sender, message)
}
