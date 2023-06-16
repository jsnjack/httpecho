/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var bindAddr string
var certPath string

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start HTTP echo server",
	Long: `List of query parameters to adjust a response behaviour:
	sleep - delay response for specified duration. Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h" (?sleep=5s)
	status - return the response with specified status code (?status=200)
	size - on top of headers, add data of specific size to response body. Supported units are "KB", "MB", "GB" (?size=200KB)
	header - add additional header to response (?header=Content-Type:text/plain)
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true

		http.HandleFunc("/", requestHandle)

		// Certificate is not provided, start http server
		if certPath == "" {
			server := &http.Server{
				Addr: bindAddr,
			}

			fmt.Printf("Starting HTTP server on %s...\n", bindAddr)
			log.Fatal(server.ListenAndServe())
			return nil
		}

		//Start https server

		data, err := readCert(certPath)
		if err != nil {
			return err
		}

		certs, err := extractCerts(data)
		if err != nil {
			return err
		}
		if len(certs) == 0 {
			return fmt.Errorf("unable to extract certificates")
		}

		privKey, err := extractPrivateKey(data)
		if err != nil {
			return err
		}

		var cert tls.Certificate
		for _, item := range certs {
			cert.Certificate = append(cert.Certificate, item.Raw)
		}
		cert.PrivateKey = privKey

		cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
		server := &http.Server{
			Addr:      bindAddr,
			TLSConfig: cfg,
		}
		fmt.Printf("Starting HTTPS server on %s...\n", bindAddr)
		log.Fatal(server.ListenAndServeTLS("", ""))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
	startCmd.Flags().StringVarP(&bindAddr, "bind", "b", "127.0.0.1:8008", "Address to bind to, e.g. <ip>:<port>")
	startCmd.Flags().StringVarP(&certPath, "cert", "c", "", "Path to certificate file")
}

func requestHandle(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	logID := generateRandomString(5)
	logger := log.New(os.Stdout, "["+logID+"] ", log.Lmicroseconds)

	// Handle special flags

	// Status code
	statusStr := r.FormValue("status")
	status, err := strconv.Atoi(statusStr)
	if err == nil {
		w.WriteHeader(status)
	}

	// Add extra headers
	err = r.ParseForm()
	if err == nil {
		for k, v := range r.Form {
			if k == "header" {
				for _, h := range v {
					headerKey, headerValue := parseHeader(h)
					if headerKey != "" {
						w.Header().Set(headerKey, headerValue)
					}
				}
			}
		}
	}

	// Delay response
	sleepStr := r.FormValue("sleep")
	sleep, err := time.ParseDuration(sleepStr)
	if err == nil {
		time.Sleep(sleep)
	}

	// Add all request headers to response body
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	for k, v := range r.Header {
		w.Write([]byte(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ","))))
	}

	// Generate extra body content
	sizeStr := r.FormValue("size")
	data, err := generatePayload(sizeStr)
	if err == nil {
		w.Write(data)
	}

	defer func() {
		duration := time.Since(startTime)
		logger.Printf("%s %s [took %s]\n", r.Method, r.URL, duration)
	}()
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// GenerateRandomString generates random string of requested length
func generateRandomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func generatePayload(sizeStr string) ([]byte, error) {
	if sizeStr == "" || len(sizeStr) < 3 {
		return nil, fmt.Errorf("bad size")
	}
	size, err := strconv.ParseFloat(sizeStr[:len(sizeStr)-2], 64)
	if err != nil {
		return nil, err
	}

	unit := sizeStr[len(sizeStr)-2:]
	switch strings.ToUpper(unit) {
	case "KB":
		size *= 1024
	case "MB":
		size *= 1024 * 1024
	case "GB":
		size *= 1024 * 1024 * 1024
	}

	payload := make([]byte, int(size))
	for i := range payload {
		payload[i] = 'a'
	}
	return payload, nil
}

func extractCerts(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		item, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		format := "%+19s: %s\n"
		fmt.Printf(format, "found certificate", item.Subject)
		fmt.Printf(format, "issuer", item.Issuer)
		fmt.Printf(format, "expires in", fmt.Sprintf("%.0f days\n", item.NotAfter.Sub(time.Now()).Hours()/24))

		if item.NotAfter.Before(time.Now()) {
			return nil, fmt.Errorf("the certificate has expired on %v", item.NotAfter)
		}
		if item.NotBefore.After(time.Now()) {
			return nil, fmt.Errorf("the certificate is valid after %v", item.NotBefore)
		}
		certs = append(certs, item)
	}
	return certs, nil
}

func extractPrivateKey(data []byte) (crypto.PrivateKey, error) {
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if !strings.Contains(block.Type, "PRIVATE KEY") || len(block.Headers) != 0 {
			continue
		}

		item, err := parsePrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return item, nil
	}
	return nil, fmt.Errorf("private key not found")
}

// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS#1 private keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("failed to parse private key")
}

func readCert(filename string) ([]byte, error) {
	var data []byte
	if filename == "" {
		return nil, fmt.Errorf("provide certificate file")
	}
	_, err := os.Stat(filename)
	if err == nil {
		data, err = ioutil.ReadFile(filename)
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	return nil, err
}

// parseHeader parses header in form of key:value
func parseHeader(data string) (string, string) {
	parts := strings.SplitN(data, ":", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}
