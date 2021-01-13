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
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var startPort int

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start HTTP echo server",
	Long: `List of query parameters to adjust a response behaviour:
    sleep - delay response for specified duration. Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
    status - return the response with specified status code
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true

		http.HandleFunc("/", requestHandle)

		server := &http.Server{
			Addr: fmt.Sprintf(":%d", startPort),
		}
		fmt.Printf("Starting HTTP server on port %d...\n", startPort)
		log.Fatal(server.ListenAndServe())
		return nil
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
	startCmd.Flags().IntVarP(&startPort, "port", "p", 8008, "Port to start HTTP server on")
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

	// Delay response
	sleepStr := r.FormValue("sleep")
	sleep, err := time.ParseDuration(sleepStr)
	if err == nil {
		time.Sleep(sleep)
	}

	// Add all request headers to response body
	w.Header().Set("Content-Type", "text/plain")
	for k, v := range r.Header {
		w.Write([]byte(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ","))))
	}

	defer func() {
		duration := time.Now().Sub(startTime)
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
