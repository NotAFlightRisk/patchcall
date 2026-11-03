package notify

import (
	"cmp"
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"net/url"
	"strings"
	"time"
)

// mail sends over smtp:// (STARTTLS when offered) or smtps://, logging in if the URL has a user
func mail(cfg Config, m Message) error {
	server, err := url.Parse(cfg.SMTPURL)
	if err != nil {
		return err
	}
	host, port := server.Hostname(), server.Port()
	secure := &tls.Config{ServerName: host}
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	var conn net.Conn
	if server.Scheme == "smtps" {
		conn, err = tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, cmp.Or(port, "465")), secure)
	} else {
		conn, err = dialer.Dial("tcp", net.JoinHostPort(host, cmp.Or(port, "587")))
	}
	if err != nil {
		return err
	}
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer client.Close()
	if ok, _ := client.Extension("STARTTLS"); ok && server.Scheme != "smtps" {
		if err := client.StartTLS(secure); err != nil {
			return err
		}
	}
	if server.User != nil {
		password, _ := server.User.Password()
		if err := client.Auth(smtp.PlainAuth("", server.User.Username(), password, host)); err != nil {
			return err
		}
	}
	recipients := strings.Split(cfg.EmailTo, ",")
	if err := client.Mail(cfg.EmailFrom); err != nil {
		return err
	}
	for _, to := range recipients {
		if err := client.Rcpt(strings.TrimSpace(to)); err != nil {
			return err
		}
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	fmt.Fprintf(writer, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\n"+
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n\r\n%s\r\n",
		cfg.EmailFrom, cfg.EmailTo, mime.QEncoding.Encode("utf-8", m.Title),
		time.Now().Format(time.RFC1123Z), strings.ReplaceAll(m.Body, "\n", "\r\n"), m.URL)
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}
