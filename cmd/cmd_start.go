/*
Copyright © 2021 YAUHEN SHULITSKI <jsnjack@gmail.com>

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
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/valyala/fasthttp"
)

var bindAddr string
var certPath string

const ResetColor = "\033[0m"
const RedColor = "\033[31m"
const GreenColor = "\033[32m"
const YellowColor = "\033[33m"
const BlueColor = "\033[34m"
const PurpleColor = "\033[35m"
const CyanColor = "\033[36m"
const GrayColor = "\033[37m"
const WhiteColor = "\033[97m"
const CrossedColor = "\033[9m"

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start HTTP echo server",
	Long: `List of query parameters to adjust a response behaviour:
	sleep - delay response for specified duration. Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h" (?sleep=5s)
	status - return the response with specified status code (?status=200)
	size - on top of headers, add data of specific size to response body. Supported units are "KB", "MB", "GB" (?size=200KB)
	header - add additional header to response (?header=Content-Type:text/plain)
	verbose - log full request to stdout (?verbose=true)
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true

		requestHandler := func(ctx *fasthttp.RequestCtx) {
			requestHandle(ctx)
		}

		// Certificate is not provided, start http server
		if certPath == "" {
			fmt.Printf("Starting HTTP server on %s...\n", bindAddr)
			log.Fatal(fasthttp.ListenAndServe(bindAddr, requestHandler))
			return nil
		}

		// Start https server
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
		fmt.Printf("Starting HTTPS server on %s...\n", bindAddr)
		server := &fasthttp.Server{
			Handler:   requestHandler,
			TLSConfig: cfg,
		}
		log.Fatal(server.ListenAndServeTLS(bindAddr, "", ""))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
	startCmd.Flags().StringVarP(&bindAddr, "bind", "b", "127.0.0.1:8008", "Address to bind to, e.g. <ip>:<port>")
	startCmd.Flags().StringVarP(&certPath, "cert", "c", "", "Path to certificate file")
}

func requestHandle(ctx *fasthttp.RequestCtx) {
	startTime := time.Now()
	logID := generateRandomString(5)
	logger := log.New(os.Stdout, "["+logID+"] ", log.Lmicroseconds)
	var err error

	// Extract query parameters
	requestVerboseStr := string(ctx.QueryArgs().Peek("verbose"))
	statusStr := string(ctx.QueryArgs().Peek("status"))
	sleepStr := string(ctx.QueryArgs().Peek("sleep"))
	sizeStr := string(ctx.QueryArgs().Peek("size"))

	// Log request
	shouldLogRequests := false
	if requestVerboseStr != "" {
		shouldLogRequests, err = strconv.ParseBool(requestVerboseStr)
		if err != nil {
			shouldLogRequests = false
		}
	}
	if shouldLogRequests {
		requestLine := fmt.Sprintf("%s %s %s", ctx.Method(), ctx.RequestURI(), ctx.Request.Header.Protocol())
		printByLine(requestLine, GreenColor, "", logger)
		data := string(ctx.Request.Header.RawHeaders())
		printByLine(data, GreenColor, "\r\n", logger)
		body := ctx.Request.Body()
		switch string(ctx.Request.Header.ContentType()) {
		case "application/json":
			var prettyJSON bytes.Buffer
			err = json.Indent(&prettyJSON, body, "", "  ")
			if err == nil {
				printByLine(prettyJSON.String(), YellowColor, "\n", logger)
			} else {
				printByLine(string(body), YellowColor, "", logger)
			}
		default:
			printByLine(string(body), YellowColor, "", logger)
		}
	}

	// Status code
	status, err := strconv.Atoi(statusStr)
	if err == nil {
		ctx.SetStatusCode(status)
	}

	// Add extra headers
	ctx.QueryArgs().VisitAll(func(k, v []byte) {
		if string(k) == "header" {
			headerKey, headerValue := parseHeader(string(v))
			if headerKey != "" {
				ctx.Response.Header.Set(headerKey, headerValue)
			}
		}
	})

	// Delay response
	if sleepStr != "" {
		logger.Printf("sleeping for %s\n", sleepStr)
		sleep, err := time.ParseDuration(sleepStr)
		if err == nil {
			time.Sleep(sleep)
		}
	}

	// Add all request headers to response body
	ctx.Response.Header.Set("Content-Type", "text/plain")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.Write(ctx.Request.Header.RawHeaders())

	// Generate extra body content
	if sizeStr != "" {
		data, err := generatePayload(sizeStr)
		if err == nil {
			ctx.Write(data)
		}
	}

	defer func() {
		duration := time.Since(startTime)
		if shouldLogRequests {
			logger.Printf("took %s\n", duration)
		} else {
			logger.Printf("%s %s [took %s]\n", ctx.Method(), ctx.URI(), duration)
		}
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
		fmt.Printf(format, "expires in", fmt.Sprintf("%.0f days\n", time.Until(item.NotAfter).Hours()/24))

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
		data, err = os.ReadFile(filename)
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

func printByLine(data string, color string, separator string, logger *log.Logger) {
	if separator == "" {
		logger.Println(color + data + ResetColor)
		return
	}

	for _, line := range strings.Split(data, separator) {
		if len(line) != 0 {
			logger.Println(color + line + ResetColor)
		}
	}
}
