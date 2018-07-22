// Copyright 2018 Mathieu Lonjaret

package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mpl/basicauth"
	"github.com/mpl/simpletls"
)

const (
	idstring      = "http://golang.org/pkg/http/#ListenAndServe"
	simpleRFC3339 = "20060102"
)

var (
	help         = flag.Bool("h", false, "show this help")
	flagHost     = flag.String("host", "0.0.0.0:8080", "listening port and hostname")
	flagUserpass = flag.String("userpass", "", "optional username:password protection")
	flagTLS      = flag.Bool("tls", false, `Enable TLS.`)
	flagZoneFile = flag.String("zone", "", "zone file to update")
)

var (
	newZoneFile, oldZoneFile string
	up                       *basicauth.UserPass
	mu                       sync.Mutex // guards zone file
)

var authorizedDomains = []string{"home", "jo"}

func usage() {
	fmt.Fprintf(os.Stderr, "\t mydyndns \n")
	flag.PrintDefaults()
	os.Exit(2)
}

func makeHandler(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if e, ok := recover().(error); ok {
				http.Error(w, e.Error(), http.StatusInternalServerError)
				return
			}
		}()
		title := r.URL.Path
		w.Header().Set("Server", idstring)
		if isAllowed(r) {
			fn(w, r, title)
		} else {
			basicauth.SendUnauthorized(w, r, "mydyndns")
		}
	}
}

func isAllowed(r *http.Request) bool {
	// TODO(mpl): I should somehow also have a relation between the name to update
	// and the auth, so that Jo can only update jo.
	if *flagUserpass == "" {
		return true
	}
	return up.IsAllowed(r)
}

func updateZoneHandler(w http.ResponseWriter, r *http.Request, url string) {
	mu.Lock()
	defer mu.Unlock()
	subdomain := r.FormValue("name")
	if subdomain == "" {
		http.Error(w, "nope", 400)
		log.Printf("no name parameter in query")
		return
	}
	authorized := false
	for _, v := range authorizedDomains {
		if subdomain == v {
			authorized = true
			break
		}
	}
	if !authorized {
		http.Error(w, "nope", 400)
		log.Printf("not an authorized domain")
		return
	}
	const genericError = "cannot update zone file"
	f, err := os.Open(*flagZoneFile)
	if err != nil {
		http.Error(w, "cannot open zone file", 500)
		log.Printf("%v", err)
		f.Close()
		return
	}
	data, err := updateZone(f, subdomain, r.RemoteAddr)
	if err != nil {
		f.Close()
		if err == sameIPError {
			w.Write([]byte(r.RemoteAddr))
			return
		}
		http.Error(w, genericError, 500)
		log.Printf("%v", err)
		return
	}
	f.Close()
	if err := ioutil.WriteFile(newZoneFile, data, 0644); err != nil {
		http.Error(w, genericError, 500)
		log.Printf("%v", err)
		return
	}
	if err := rotateZoneFiles(); err != nil {
		http.Error(w, genericError, 500)
		log.Printf("%v", err)
		return
	}
	if err := reloadBind(); err != nil {
		http.Error(w, genericError, 500)
		log.Printf("%v", err)
		return
	}
	w.Write([]byte(r.RemoteAddr))
}

var updateStampRgx = regexp.MustCompile(`(\s*)(\d{8})(\d+);`)

var sameIPError = errors.New("IP in update is already the one for the domain")

func updateZone(r io.Reader, name, addr string) ([]byte, error) {
	ip, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("could not split host and port in addr %v, %v", addr, err)
	}
	if IP := net.ParseIP(ip); IP == nil {
		return nil, fmt.Errorf("not a valid IP: %q", ip)
	}
	var buf bytes.Buffer
	sc := bufio.NewScanner(r)
	dateDone, ipDone := false, false
	for sc.Scan() {
		l := sc.Text()
		if dateDone && ipDone {
			if err := writeLine(l, &buf); err != nil {
				return nil, err
			}
			continue
		}

		if dateDone {
			fields := strings.Fields(l)
			if len(fields) != 4 || fields[1] != "IN" || fields[2] != "A" || fields[0] != name {
				if err := writeLine(l, &buf); err != nil {
					return nil, err
				}
				continue
			}
			if fields[3] == ip {
				return nil, sameIPError
			}
			newValue := fmt.Sprintf("%s\tIN\tA\t%s", name, ip)
			if err := writeLine(newValue, &buf); err != nil {
				return nil, err
			}
			ipDone = true
			continue
		}

		m := updateStampRgx.FindStringSubmatch(l)
		if m != nil {
			println(l, "MATCHED")
		}
		if m == nil || len(m) != 4 {
			if err := writeLine(l, &buf); err != nil {
				return nil, err
			}
			continue
		}
		datePart := m[2]
		if _, err := time.Parse(simpleRFC3339, datePart); err != nil {
			log.Printf("%v", err)
			if err := writeLine(l, &buf); err != nil {
				return nil, err
			}
			continue
		}
		i, err := strconv.Atoi(m[3])
		if err != nil {
			log.Printf("%v", err)
			if err := writeLine(l, &buf); err != nil {
				return nil, err
			}
			continue
		}
		whiteSpace := m[1]
		var updateStamp string
		today := time.Now().Format(simpleRFC3339)
		if datePart == today {
			i++
			updateStamp = fmt.Sprintf("%s%s%d;", whiteSpace, today, i)
		} else {
			println(today, "VS", datePart)
			updateStamp = whiteSpace + today + "1;"
		}
		if err := writeLine(updateStamp, &buf); err != nil {
			return nil, err
		}
		dateDone = true
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !ipDone {
		return nil, fmt.Errorf("ip for %v was not updated", name)
	}
	if !dateDone {
		return nil, fmt.Errorf("timestamp was not updated")
	}
	return buf.Bytes(), nil
}

func writeLine(l string, buf *bytes.Buffer) error {
	_, err := buf.Write([]byte(l + "\n"))
	return err
}

// we use mv instead of os.Rename, so we can have sudo for specific commands,
// and not run the whole thing as root.
// it requires sudo with NOPASSWD for bind user for these commands.
func rotateZoneFiles() error {
	out, err := exec.Command("sudo", "cp", *flagZoneFile, oldZoneFile).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v, %s", err, out)
	}
	out, err = exec.Command("sudo", "mv", newZoneFile, *flagZoneFile).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v, %s", err, out)
	}
	return nil
}

func reloadBind() error {
	out, err := exec.Command("sudo", "systemctl", "reload", "bind9").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v, %s", err, out)
	}
	return nil
}

func initUserPass() {
	if *flagUserpass == "" {
		return
	}
	var err error
	up, err = basicauth.New(*flagUserpass)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	flag.Parse()
	if *flagZoneFile == "" {
		usage()
	}

	// this is somewhat safe because I run the whole thing as bind, with:
	// sudo -u bind /usr/local/bin/mydyndns -zone /etc/bind/zones/granivo.re.db
	// and that /etc/bind/zones/mydyndns is drwxrwxr-x 2 root bind
	// TODO(mpl): last detail is the let's encrypt cache that user bind needs
	// access to.
	bindWIPdir := filepath.Join(filepath.Dir(*flagZoneFile), "mydyndns")
	newZoneFile = filepath.Join(bindWIPdir, filepath.Base(*flagZoneFile)) + ".new"
	oldZoneFile = *flagZoneFile + ".old"

	initUserPass()

	var err error
	var listener net.Listener
	if *flagTLS {
		listener, err = simpletls.Listen(*flagHost)
	} else {
		listener, err = net.Listen("tcp", *flagHost)
	}
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", *flagHost, err)
	}

	http.Handle("/update", makeHandler(updateZoneHandler))
	if err = http.Serve(listener, nil); err != nil {
		log.Fatalf("Error in http server: %v\n", err)
	}
}
