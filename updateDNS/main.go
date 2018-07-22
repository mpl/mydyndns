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
)

var (
	sleepTime = 5 * time.Minute
)

func main() {
	flag.Parse()
	if *flagHost == "" {
		log.Fatal("-host must be specified")
	}
	if *flagDomain == "" {
		log.Fatal("-domain must be specified")
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
