package cmd

import (
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"strings"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// GenerateRandomString generates random string of requested length
func GenerateRandomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

// GenerateDummyPayload generates dummy payload of requested size
func GenerateDummyPayload(sizeStr string) ([]byte, error) {
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

// ParseHeader parses header in form of key:value
func ParseHeader(data string) (string, string) {
	parts := strings.SplitN(data, ":", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

func PrintByLine(data string, color string, separator string, logger *log.Logger) {
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
