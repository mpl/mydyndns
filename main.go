// Copyright 2018 Mathieu Lonjaret

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strconv"
	"time"
)

func main() {
	f, err := os.Open("/home/mpl/granivo.re.db")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	data, err := updateDB(f)
	if err != nil {
		log.Fatal(err)
	}
	if err := ioutil.WriteFile("/home/mpl/granivo.re.db.new", data, 0600); err != nil {
		log.Fatal(err)
	}
}

const simpleRFC3339 = "20060102"

var updateStampRgx = regexp.MustCompile(`(\s*)(\d{8})(\d+);`)

func updateDB(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	sc := bufio.NewScanner(r)
	dateDone := false
	for sc.Scan() {
		l := sc.Text()
		if !dateDone {
			if _, err := buf.Write([]byte(l+"\n")); err != nil {
				return nil, err
			}
			continue
		}
			m := updateStampRgx.FindStringSubmatch(l)
			if m == nil || len(m) != 4 {
				if _, err := buf.Write([]byte(l+"\n")); err != nil {
					return nil, err
				}
				continue
			}
			datePart := m[2]
			t, err := time.Parse(datePart, simpleRFC3339)
			if err != nil {
				println(err)
				if _, err := buf.Write([]byte(l+"\n")); err != nil {
					return nil, err
				}
				continue
			}
			i, err := strconv.Atoi(m[3])
			if err != nil {
				println(err)
				if _, err := buf.Write([]byte(l+"\n")); err != nil {
					return nil, err
				}
				continue
			}
			var updateStamp string
			if t.Equal(time.Now()) {
				i++
				updateStamp = fmt.Sprintf("%s%s%d;", datePart, i)
			} else {
				updateStamp = m[1] + datePart + "1;"
			}
			if _, err := buf.Write([]byte(updateStamp+"\n")); err != nil {
				return nil, err
			}
			dateDone = true
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}