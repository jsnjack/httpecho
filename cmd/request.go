package cmd

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

// EchoRequest represents a request to echo server
type EchoRequest struct {
	Sleep                  time.Duration // Sleep duration before responding
	ResponseStatusCode     int           // Status code to return, by default 200
	ResponseBodySize       int           // Total size of response body, bytes
	ResponseHeaders        map[string]string
	VerboseLoggingToStdout bool
	HTMLMode               bool // If true, response will be in HTML format, browser optimized, otherwise plain text
}

func NewEchoRequest(qp *fasthttp.Args, rh *fasthttp.RequestHeader) (*EchoRequest, error) {
	req := EchoRequest{}

	// Parse query parameters

	// Handle sleep parameter
	sleepStr := string(qp.Peek("sleep"))
	if sleepStr != "" {
		sleep, err := time.ParseDuration(sleepStr)
		if err != nil {
			return nil, err
		}
		req.Sleep = sleep
	}

	// Handle status parameter
	req.ResponseStatusCode = 200
	statusStr := string(qp.Peek("status"))
	if statusStr != "" {
		status, err := strconv.Atoi(statusStr)
		if err != nil {
			return nil, err
		}
		req.ResponseStatusCode = status
	}

	// Handle size parameter
	sizeStr := string(qp.Peek("size"))
	if sizeStr != "" {
		if len(sizeStr) < 3 {
			return nil, fmt.Errorf("bad size, should be in format <number><unit> where unit is one of KB, MB, GB")
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
		req.ResponseBodySize = int(size)
	}

	// Handle verbose parameter
	verboseStr := string(qp.Peek("verbose"))
	if verboseStr != "" {
		verbose, err := strconv.ParseBool(verboseStr)
		if err != nil {
			return nil, err
		}
		req.VerboseLoggingToStdout = verbose
	}

	// Handle headers parameter
	headersToAdd := qp.PeekMulti("header")
	req.ResponseHeaders = make(map[string]string)
	for _, header := range headersToAdd {
		key, value := ParseHeader(string(header))
		if key == "" {
			return nil, fmt.Errorf("bad header, should be in format <key>:<value>")
		}
		req.ResponseHeaders[key] = value
	}

	// Check if user agent accepts html
	rh.VisitAll(func(key, value []byte) {
		if strings.EqualFold(string(key), "Accept") && strings.Contains(string(value), "text/html") {
			req.HTMLMode = true
		}
	})

	return &req, nil

}
