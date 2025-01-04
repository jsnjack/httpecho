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
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/valyala/fasthttp"
)

var bindAddr string
var certPath string

//go:embed templates/*
var TemplatesStorage embed.FS

//go:embed static/*
var StaticStorage embed.FS

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

	ctx.Response.Header.Set("Server", "httpecho")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")

	defer func() {
		duration := time.Since(startTime)
		logger.Printf("%s %s [took %s]\n", ctx.Method(), ctx.URI(), duration)
	}()

	// Handle requests to static files
	if strings.HasPrefix(string(ctx.Path()), "/static/") {
		content, err := StaticStorage.ReadFile(string(ctx.Path())[1:])
		if err == nil {
			ctx.SetContentType("text/css")
			ctx.SetStatusCode(fasthttp.StatusOK)
			ctx.Response.Header.Set("Cache-Control", "public, max-age=31536000")
			ctx.Write(content)
			return
		} else {
			logger.Printf("error: %s\n", err)
		}
	}

	echoReq, err := NewEchoRequest(ctx.QueryArgs(), &ctx.Request.Header)
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

	// Sleep
	if echoReq.Sleep > 0 {
		time.Sleep(echoReq.Sleep)
	}

	// Status code
	ctx.SetStatusCode(echoReq.ResponseStatusCode)

	// Add extra headers provided in query parameters
	for key, value := range echoReq.ResponseHeaders {
		ctx.Response.Header.Set(key, value)
	}

	rawHeaders := ctx.Request.Header.RawHeaders()

	// Generate dummy payload to response body
	dummyPayload := make([]byte, 0)
	if echoReq.ResponseBodySize > 0 && echoReq.ResponseBodySize > len(rawHeaders) {
		dummyPayload = make([]byte, echoReq.ResponseBodySize-len(rawHeaders))
		for i := range dummyPayload {
			dummyPayload[i] = 'a'
		}
	}

	// In case of HTML mode, assume that the request is coming from a browser and
	// make the response more browser-friendly
	if echoReq.HTMLMode {
		ctx.Response.Header.Set("Content-Type", "text/html")

		// Read the template content
		tmplContent, err := TemplatesStorage.ReadFile("templates/echo.html.tpl")
		if err != nil {
			logger.Printf("error: %s\n", err)
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.Write([]byte(err.Error()))
			return
		}

		// Parse the template content
		tmpl, err := template.New("template").Parse(string(tmplContent))
		if err != nil {
			logger.Printf("error: %s\n", err)
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.Write([]byte(err.Error()))
			return
		}

		// Render the template with the provided data
		err = tmpl.Execute(ctx, map[string]interface{}{
			"rawHeaders":   strings.Split(string(rawHeaders), "\r\n"),
			"dummyPayload": string(dummyPayload),
		})
		if err != nil {
			logger.Printf("error: %s\n", err)
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.Write([]byte(err.Error()))
			return
		}
	} else {
		ctx.Response.Header.Set("Content-Type", "text/plain")

		// Add all request headers to response body
		ctx.Write(rawHeaders)

		// Add dummy payload to response body
		ctx.Write(dummyPayload)
	}
}
