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
	"time"

	"github.com/spf13/cobra"
)

var startPort int

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start HTTP echo server",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true

		http.HandleFunc("/", requestHandle)

		server := &http.Server{
			Addr: fmt.Sprintf(":%d", startPort),
		}
		log.Printf("Starting HTTP server on port %d...\n", startPort)
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
	logID := GenerateRandomString(5)
	logger := log.New(os.Stdout, "["+logID+"] ", log.Lmicroseconds)
	defer func() {
		duration := time.Now().Sub(startTime)
		logger.Printf("%s %s [took %s]\n", r.Method, r.URL, duration)
	}()
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// GenerateRandomString generates random string of requested length
func GenerateRandomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
