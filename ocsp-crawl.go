// This is an example program that demonstrates processing certificates from a
// log entries file. It looks for certificates that contain ".corp" names and
// prints them to stdout.

package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jsha/certificatetransparency"
	"golang.org/x/crypto/ocsp"
)

var logURL = flag.String("url", "https://log.certly.io", "url of CT log")
var logKey = flag.String("key", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECyPLhWKYYUgEc+tUXfPQB4wtGS2MNvXrjwFCCnyYJifBtd2Sk7Cu+Js9DNhMTh35FftHaHu6ZrclnNBKwmbbSA==", "base64-encoded CT log key")
var fileName = flag.String("file", "certly.log", "file in which to cache log data.")
var v = flag.Bool("v", false, "verbose")
var skipUpdate = flag.Bool("skip-update", false, "skip update")

type data struct {
	serial      string
	notBefore   time.Time
	nextUpdate  time.Time
	thisUpdate  time.Time
	ocspLatency time.Duration
	ocspErr     error
	names       []string
	url         string
}

var statuses map[int]string = make(map[int]string, 4)

func main() {
	flag.Parse()
	if logURL == nil || logKey == nil || fileName == nil {
		flag.PrintDefaults()
		return
	}
	statuses[ocsp.Good] = "good"
	statuses[ocsp.Revoked] = "revoked"
	statuses[ocsp.Unknown] = "unknown"
	statuses[ocsp.ServerFailed] = "fail"

	pemPublicKey := fmt.Sprintf(`-----BEGIN PUBLIC KEY-----
%s
-----END PUBLIC KEY-----`, *logKey)
	ctLog, err := certificatetransparency.NewLog(*logURL, pemPublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize log: %s\n", err)
		os.Exit(1)
	}

	file, err := os.OpenFile(*fileName, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open entries file: %s\n", err)
		os.Exit(1)
	}
	defer file.Close()

	entriesFile := certificatetransparency.EntriesFile{file}

	if !*skipUpdate {
		sth, err := ctLog.GetSignedTreeHead()
		if err != nil {
			fmt.Fprintf(os.Stderr, "GetSignedTreeHead: %s\n", err)
			os.Exit(1)
		}
		fmt.Printf("%d total entries at %s\n", sth.Size, sth.Time.Format(time.ANSIC))

		count, err := entriesFile.Count()
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nFailed to read entries file: %s\n", err)
			os.Exit(1)
		}
		if count < sth.Size {
			_, err = ctLog.DownloadRange(file, nil, count, sth.Size)
			if err != nil {
				fmt.Fprintf(os.Stderr, "\nFailed to update CT log: %s\n", err)
				os.Exit(1)
			}
		}
		entriesFile.Seek(0, 0)
		treeHash, err := entriesFile.HashTree(nil, sth.Size)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error hashing tree: %s", err)
			os.Exit(1)
		}
		if !bytes.Equal(treeHash[:], sth.Hash) {
			fmt.Fprintf(os.Stderr, "Hashes do not match! Calculated: %x, STH contains %x\n", treeHash, sth.Hash)
			os.Exit(1)
		}
		fmt.Println("Hashes match! Calculated: %s, STH contains %s\n", hex.EncodeToString(treeHash[:]), hex.EncodeToString(sth.Hash[:]))
		entriesFile.Seek(0, 0)
	}

	dataChan := make(chan data)

	go func() {
		entriesFile.Map(func(ent *certificatetransparency.EntryAndPosition, err error) {
			if err != nil {
				return
			}

			cert, err := x509.ParseCertificate(ent.Entry.X509Cert)
			if err != nil {
				return
			}
			if cert.Issuer.CommonName != "Let's Encrypt Authority X1" {
				return
			}
			if time.Now().After(cert.NotAfter) {
				return
			}

			var issuer *x509.Certificate
			if len(ent.Entry.ExtraCerts) > 0 {
				issuer, err = x509.ParseCertificate(ent.Entry.ExtraCerts[0])
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to parse issuer: %s\n", err)
					return
				}
			}
			if len(cert.OCSPServer) == 0 {
				if cert.Issuer.CommonName != "Merge Delay Intermediate 1" {
					fmt.Fprintf(os.Stderr, "No OCSP Server for %s\n", cert.Issuer.CommonName)
				}
				return
			}
			ocspServer := cert.OCSPServer[0]
			req, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{})
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating OCSP request: %s\n", err)
				return
			}
			url := fmt.Sprintf("%s%s", ocspServer, base64.StdEncoding.EncodeToString(req))
			start := time.Now()
			httpResponse, err := http.Post(ocspServer, "application/ocsp-request", bytes.NewBuffer(req))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching OCSP: %s %s\n", err, url)
				return
			}
			defer httpResponse.Body.Close()
			datum := data{
				serial:      fmt.Sprintf("%032x", cert.SerialNumber),
				names:       cert.DNSNames,
				ocspLatency: time.Now().Sub(start),
				notBefore:   cert.NotBefore,
				url:         url,
			}
			if datum.ocspLatency > time.Second {
				fmt.Printf("slow response (%dms) for %x: %s\n", datum.ocspLatency/time.Millisecond, cert.SerialNumber, url)
			}
			names := strings.Join(cert.DNSNames, ", ")
			if err != nil {
				datum.ocspErr = fmt.Errorf("error fetching OCSP for %s %s: %s\n", names, url, err)
				dataChan <- datum
				return
			}
			ocspResponse, err := ioutil.ReadAll(httpResponse.Body)
			if err != nil {
				datum.ocspErr = fmt.Errorf("error reading OCSP for %s %s: %s\n", names, url, err)
				dataChan <- datum
				return
			}
			parsedResponse, err := ocsp.ParseResponse(ocspResponse, issuer)
			if err != nil {
				datum.ocspErr = fmt.Errorf("error parsing OCSP response for %s %s: %s\n", names, url, err)
				dataChan <- datum
				return
			}
			datum.nextUpdate = parsedResponse.NextUpdate
			datum.thisUpdate = parsedResponse.ThisUpdate
			dataChan <- datum
		})
		close(dataChan)
	}()
	processData(dataChan)
}

type int64slice []int64

func (a int64slice) Len() int           { return len(a) }
func (a int64slice) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a int64slice) Less(i, j int) bool { return a[i] < a[j] }

func processData(in <-chan data) {
	begin := time.Now()
	var latestIssue time.Time
	var totalLatency time.Duration
	latencies := make(int64slice, 10000)
	distinct := make(map[string]bool)
	for datum := range in {
		if *v {
			fmt.Printf("%s %s %s\n", datum.notBefore, datum.serial, strings.Join(datum.names, ", "))
		}
		if datum.notBefore.After(latestIssue) {
			latestIssue = datum.notBefore
		}
		if datum.ocspErr != nil {
			fmt.Fprintf(os.Stderr, "%s", datum.ocspErr)
		}
		if begin.After(datum.nextUpdate) {
			fmt.Fprintf(os.Stderr, "Badly out of date response for %s: %s\n", datum.serial, datum.thisUpdate)
		}
		if begin.Sub(datum.thisUpdate) > time.Hour*24*4 {
			fmt.Fprintf(os.Stderr, "Out of date response for %s: %s %s\n", datum.serial, datum.thisUpdate, datum.url)
		}
		latencies = append(latencies, int64(datum.ocspLatency))
		totalLatency += datum.ocspLatency
		distinct[datum.serial] = true
	}
	sort.Sort(latencies)
	timeSinceLatest := begin.Sub(latestIssue)
	median := time.Duration(latencies[len(latencies)/2])
	mean := time.Duration(totalLatency / time.Duration(len(latencies)))
	ninetieth := time.Duration(latencies[int(len(latencies)*9/10)])
	max := time.Duration(latencies[len(latencies)-1])
	fmt.Printf("Count: %d %d\n", len(latencies), len(distinct))
	fmt.Printf("Latest issue: %v\n", timeSinceLatest)
	fmt.Printf("Latencies: %dms median, %dms mean, %dms 90th, %dms max\n",
		median/time.Millisecond, mean/time.Millisecond, ninetieth/time.Millisecond,
		max/time.Millisecond)
}
