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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/valyala/fasthttp"
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
		data, err := ReadCert(certPath)
		if err != nil {
			return err
		}

		certs, err := ExtractCerts(data)
		if err != nil {
			return err
		}
		if len(certs) == 0 {
			return fmt.Errorf("unable to extract certificates")
		}

		privKey, err := ExtractPrivateKey(data)
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
	logID := GenerateRandomString(5)
	logger := log.New(os.Stdout, "["+logID+"] ", log.Lmicroseconds)
	var err error

	echoReq, err := NewEchoRequest(ctx.QueryArgs())
	if err != nil {
		logger.Printf("error: %s\n", err)
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		return
	}

	if echoReq.VerboseLoggingToStdout {
		requestLine := fmt.Sprintf("%s %s %s", ctx.Method(), ctx.RequestURI(), ctx.Request.Header.Protocol())
		PrintByLine(requestLine, GreenColor, "", logger)
		data := string(ctx.Request.Header.RawHeaders())
		PrintByLine(data, GreenColor, "\r\n", logger)
		body := ctx.Request.Body()
		switch string(ctx.Request.Header.ContentType()) {
		case "application/json":
			var prettyJSON bytes.Buffer
			err = json.Indent(&prettyJSON, body, "", "  ")
			if err == nil {
				PrintByLine(prettyJSON.String(), YellowColor, "\n", logger)
			} else {
				PrintByLine(string(body), YellowColor, "", logger)
			}
		default:
			PrintByLine(string(body), YellowColor, "", logger)
		}
	}

	// Status code
	ctx.SetStatusCode(echoReq.ResponseStatusCode)

	// Set default response headers
	ctx.Response.Header.Set("Content-Type", "text/plain")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.Response.Header.Set("Server", "httpecho")

	// Add extra headers provided in query parameters
	for key, value := range echoReq.ResponseHeaders {
		ctx.Response.Header.Set(key, value)
	}

	// Add all request headers to response body
	rawHeaders := ctx.Request.Header.RawHeaders()
	ctx.Write(rawHeaders)

	// Add dummy payload to response body
	if echoReq.ResponseBodySize > 0 && echoReq.ResponseBodySize > len(rawHeaders) {
		payload := make([]byte, echoReq.ResponseBodySize-len(rawHeaders))
		for i := range payload {
			payload[i] = 'a'
		}
		ctx.Write(payload)
	}

	// Sleep
	if echoReq.Sleep > 0 {
		time.Sleep(echoReq.Sleep)
	}

	defer func() {
		duration := time.Since(startTime)
		if echoReq.VerboseLoggingToStdout {
			logger.Printf("took %s\n", duration)
		} else {
			logger.Printf("%s %s [took %s]\n", ctx.Method(), ctx.URI(), duration)
		}
	}()
}
