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
	"crypto/tls"
	"embed"
	"fmt"
	"html/template"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/valyala/fasthttp"
	bolt "go.etcd.io/bbolt"
)

var bindAddr string
var certPath string
var dbFilename string

//go:embed templates/*
var TemplatesStorage embed.FS

//go:embed static/*
var StaticStorage embed.FS

// DB is the Bolt db
var DB *bolt.DB

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

		var err error
		DB, err = bolt.Open(dbFilename, 0644, nil)
		if err != nil {
			log.Fatal(err)
		}
		defer DB.Close()

		err = DB.Update(func(tx *bolt.Tx) error {
			_, err := tx.CreateBucketIfNotExists(StorageBucket)
			return err
		})
		if err != nil {
			log.Fatal(err)
		}

		requestHandler := func(ctx *fasthttp.RequestCtx) {
			requestHandle(ctx)
		}

		// Certificate is not provided, start http server
		if certPath == "" {
			fmt.Printf("Starting HTTP server on http://%s...\n", bindAddr)
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
		fmt.Printf("Starting HTTPS server on https://%s...\n", bindAddr)
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
	startCmd.Flags().StringVarP(&bindAddr, "bind", "b", "127.0.0.1:8008", "address to bind to, e.g. <ip>:<port>")
	startCmd.Flags().StringVarP(&certPath, "cert", "c", "", "path to certificate file")
	startCmd.Flags().StringVarP(&dbFilename, "db", "d", "httpecho.db", "path to database file")
}

func requestHandle(ctx *fasthttp.RequestCtx) {
	startTime := time.Now()
	logID := GenerateRandomString(5)
	logger := log.New(os.Stdout, "["+logID+"] ", log.Lmicroseconds)
	var err error

	// Set default headers
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

	// Parse query paramaters
	echoReq, err := NewEchoRequest(ctx.QueryArgs(), &ctx.Request.Header, string(ctx.Path()))
	if err != nil {
		logger.Printf("error: %s\n", err)
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		return
	}

	// Dump the incoming request
	dumpedRequest := NewDumpedRequest(ctx)
	if echoReq.VerboseLoggingToStdout {
		dumpedRequest.LogWithColours(logger)
	}

	// Save the request to the database
	if echoReq.ShouldBeRecorded() {
		reqId, err := SaveRequest(echoReq.Path, dumpedRequest.Bytes())
		if err != nil {
			logger.Printf("error: %s\n", err)
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.Write([]byte(err.Error()))
			return
		}
		logger.Printf("request saved with ID: %d\n", reqId)
	}

	// Handle view requests
	if echoReq.IsViewRequest() && echoReq.HTMLMode {
		savedReqMap, err := GetAllRequestForPath(echoReq.Path)
		if err != nil {
			logger.Printf("error: %s\n", err)
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.Write([]byte(err.Error()))
			return
		}

		ctx.Response.Header.Set("Content-Type", "text/html")

		// Read the template content
		tmplContent, err := TemplatesStorage.ReadFile("templates/view.html.tpl")
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
		// Sort and order the requests by ID
		var keys []uint64
		for k := range savedReqMap {
			keys = append(keys, k)
		}
		// Sort the keys
		sort.Slice(keys, func(i, j int) bool {
			return keys[i] > keys[j]
		})
		// Create a new slice with sorted requests
		sortedReqSlice := make([][]string, 0)
		for _, k := range keys {
			newEl := []string{fmt.Sprintf("%d", k), string(savedReqMap[k])}
			sortedReqSlice = append(sortedReqSlice, newEl)
		}

		// Render the template with the provided data
		err = tmpl.Execute(ctx, map[string]interface{}{
			"SortedRequests": sortedReqSlice,
		})
		if err != nil {
			logger.Printf("error: %s\n", err)
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.Write([]byte(err.Error()))
			return
		}
		return
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

	rawHeadersLen := len(ctx.Request.Header.RawHeaders())

	// Generate dummy payload to response body
	dummyPayload := make([]byte, 0)
	if echoReq.ResponseBodySize > 0 && echoReq.ResponseBodySize > rawHeadersLen {
		dummyPayload = make([]byte, echoReq.ResponseBodySize-rawHeadersLen)
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
			"dumpedRequest": dumpedRequest.String(),
			"dummyPayload":  string(dummyPayload),
		})
		if err != nil {
			logger.Printf("error: %s\n", err)
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.Write([]byte(err.Error()))
			return
		}
		return
	} else {
		ctx.Response.Header.Set("Content-Type", "text/plain")

		// Add all request headers to response body
		ctx.Write([]byte(dumpedRequest.Headers))

		// Add dummy payload to response body
		ctx.Write(dummyPayload)
	}
}
