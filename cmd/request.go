package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

// EchoRequest represents a request to echo server
type EchoRequest struct {
	Path                   string        // Request path
	Sleep                  time.Duration // Sleep duration before responding
	ResponseStatusCode     int           // Status code to return, by default 200
	ResponseBodySize       int           // Total size of response body, bytes
	ResponseHeaders        map[string]string
	VerboseLoggingToStdout bool
	HTMLMode               bool // If true, response will be in HTML format, browser optimized, otherwise plain text
	ViewMode               bool // If true, user intends to view page, no need to save it
}

// ShouldBeRecorded returns true if request should be recorded in db
func (er *EchoRequest) ShouldBeRecorded() bool {
	return !er.ViewMode && strings.HasPrefix(er.Path, "/r/")
}

// IsViewRequest returns true if request is a view request for previously saved dumped requests
func (er *EchoRequest) IsViewRequest() bool {
	return er.ViewMode && strings.HasPrefix(er.Path, "/r/")
}

func NewEchoRequest(qp *fasthttp.Args, rh *fasthttp.RequestHeader, path string) (*EchoRequest, error) {
	req := EchoRequest{
		Path: path,
	}

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
		default:
			return nil, fmt.Errorf("unsupported size unit: %s", unit)
		}
		// Limit max response size to 1GB
		if size > 1*1024*1024*1024 {
			return nil, fmt.Errorf("response size too large")
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

	// Check if view mode is enabled
	viewStr := string(qp.Peek("view"))
	if viewStr != "" {
		view, err := strconv.ParseBool(viewStr)
		if err != nil {
			return nil, err
		}
		req.ViewMode = view
	}

	return &req, nil
}

type DumpedRequest struct {
	RequestLine string
	Headers     string
	Body        string
	prettyBody  bool
}

func (dr *DumpedRequest) String() string {
	return fmt.Sprintf("%s\r\n%s\r\n%s", dr.RequestLine, dr.Headers, dr.Body)
}

func (dr *DumpedRequest) Bytes() []byte {
	return []byte(dr.String())
}

func (dr *DumpedRequest) LogWithColours(logger *log.Logger) {
	PrintByLine(dr.RequestLine, GreenColor, "", logger)
	PrintByLine(dr.Headers, GreenColor, "\r\n", logger)
	if dr.Body != "" {
		logger.Println()
	}
	if dr.prettyBody {
		PrintByLine(dr.Body, YellowColor, "\n", logger)
	} else {
		PrintByLine(dr.Body, YellowColor, "", logger)
	}
}

// NewDumpedRequest creates a new DumpedRequest from fasthttp.RequestCtx
func NewDumpedRequest(ctx *fasthttp.RequestCtx) *DumpedRequest {
	var dr DumpedRequest
	body, err := ctx.Request.BodyUncompressed()
	if err != nil {
		body = ctx.Request.Body()
	}

	switch string(ctx.Request.Header.ContentType()) {
	case "application/json":
		var prettyJSON bytes.Buffer
		err := json.Indent(&prettyJSON, body, "", "  ")
		if err == nil {
			body = prettyJSON.Bytes()
			dr.prettyBody = true

		}
	}
	dr.RequestLine = fmt.Sprintf("%s %s %s", ctx.Method(), ctx.RequestURI(), ctx.Request.Header.Protocol())
	dr.Headers = string(ctx.Request.Header.RawHeaders())
	dr.Body = string(body)
	return &dr
}
