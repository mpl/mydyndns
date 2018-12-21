// Copyright 2018 Mathieu Lonjaret

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	flagUsername = flag.String("user", "", "username")
	flagPassword = flag.String("pass", "", "password")
	flagInsecure = flag.Bool("insecure", false, "run with insecure TLS")
	flagHost     = flag.String("host", "", "DNS server to update")
	flagDomain   = flag.String("domain", "", "subdomain to update")
	flagAddUser = flag.String("adduser", "", "username:password to add")
)

var (
	sleepTime = time.Hour
)

func adduser() error {
	fields := strings.SplitN(*flagAddUser, ":", 2)
	if len(fields) != 2 {
		return fmt.Errorf("wrong username:password")
	}
	user, pass := fields[0], fields[1]
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/adduser", *flagHost),
		strings.NewReader(url.Values{"user": {user}, "password": {pass}}.Encode()))
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(*flagUsername, *flagPassword)
	cl := &http.Client{}
	if *flagInsecure {
		dialTLS := func(network, addr string) (net.Conn, error) {
			return tls.Dial(network, addr, &tls.Config{
				InsecureSkipVerify: true,
			})
		}
		cl.Transport = &http.Transport{
			DialTLS: dialTLS,
		}
	}
	resp, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	data, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("could not adduser: %d", resp.StatusCode)
	}
	if string(data) != user {
		return fmt.Errorf("could not adduser: %s", string(data))
	}
	return nil
}

func main() {
	flag.Parse()
	if *flagHost == "" {
		log.Fatal("-host must be specified")
	}
	if *flagDomain == "" {
		log.Fatal("-domain must be specified")
	}

	if *flagAddUser != "" {
		if err := adduser(); err != nil {
			log.Fatal(err)
		}
		return
	}

	first := true
	for {
		if !first {
			time.Sleep(sleepTime)
		}
		first = false
		req, err := http.NewRequest("POST", fmt.Sprintf("%s/update", *flagHost),
			strings.NewReader(url.Values{"name": {*flagDomain}}.Encode()))
		if err != nil {
			log.Printf("could not prepare request: %v", err)
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(*flagUsername, *flagPassword)
		cl := &http.Client{}
		if *flagInsecure {
			dialTLS := func(network, addr string) (net.Conn, error) {
				return tls.Dial(network, addr, &tls.Config{
					InsecureSkipVerify: true,
				})
			}
			cl.Transport = &http.Transport{
				DialTLS: dialTLS,
			}
		}
		resp, err := cl.Do(req)
		if err != nil {
			log.Printf("error with request: %v", err)
			continue
		}
		data, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Printf("could not read response: %v", err)
			continue
		}
		if resp.StatusCode != 200 {
			log.Printf("could not update IP: %s", data)
			continue
		}
		log.Printf("Server recorded my address as: %v", string(data))
	}
}
