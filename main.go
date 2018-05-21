// Copyright 2018 Mathieu Lonjaret

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func main() {
	f, err := os.Open("/home/mpl/granivo.re.db")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	data, err := updateDB(f, "home", "1.2.3.4")
	if err != nil {
		log.Fatal(err)
	}
	if err := ioutil.WriteFile("/home/mpl/granivo.re.db.new", data, 0600); err != nil {
		log.Fatal(err)
	}
}

const simpleRFC3339 = "20060102"

// var updateStampRgx = regexp.MustCompile(`(\s*)(\d{8})(.*);`)
var updateStampRgx = regexp.MustCompile(`(\s*)(\d{8})(\d+);`)

func updateDB(r io.Reader, name, ip string) ([]byte, error) {
	if IP := net.ParseIP(ip); IP == nil {
		return nil, fmt.Errorf("not a valid IP: %q", ip)
	}
	// TODO(mpl): revert timestamp/everything if actual update does not work. Probably simpler: just create new temp file and overwrite real one if everything went fine.
	var buf bytes.Buffer
	sc := bufio.NewScanner(r)
	dateDone, ipDone := false, false
	for sc.Scan() {
		l := sc.Text()
		if dateDone && ipDone {
			if _, err := buf.Write([]byte(l + "\n")); err != nil {
				return nil, err
			}
			continue
		}

		if dateDone {
			fields := strings.Fields(l)
			if len(fields) != 4 || fields[1] != "IN" || fields[2] != "A" || fields[0] != name {
				if _, err := buf.Write([]byte(l + "\n")); err != nil {
					return nil, err
				}
				continue
			}
			newValue := fmt.Sprintf("%s\tIN\tA\t%s\n", name, ip)
			if _, err := buf.Write([]byte(newValue)); err != nil {
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
			if _, err := buf.Write([]byte(l + "\n")); err != nil {
				return nil, err
			}
			continue
		}
		datePart := m[2]
		if _, err := time.Parse(simpleRFC3339, datePart); err != nil {
			log.Printf("%v", err)
			if _, err := buf.Write([]byte(l + "\n")); err != nil {
				return nil, err
			}
			continue
		}
		i, err := strconv.Atoi(m[3])
		if err != nil {
			log.Printf("%v", err)
			if _, err := buf.Write([]byte(l + "\n")); err != nil {
				return nil, err
			}
			continue
		}
		whiteSpace := m[1]
		var updateStamp string
		today := time.Now().Format(simpleRFC3339)
		if datePart == today {
			i++
			updateStamp = fmt.Sprintf("%s%s%d;\n", whiteSpace, today, i)
		} else {
			println(today, "VS", datePart)
			updateStamp = whiteSpace + today + "1;\n"
		}
		if _, err := buf.Write([]byte(updateStamp)); err != nil {
			return nil, err
		}
		dateDone = true
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
