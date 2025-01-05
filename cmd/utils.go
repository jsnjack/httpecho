package cmd

import (
	"log"
	"math/rand"
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

// ParseHeader parses header in form of key:value
func ParseHeader(data string) (string, string) {
	parts := strings.SplitN(data, ":", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

func PrintByLine(data string, color string, separator string, logger *log.Logger) {
	if data == "" {
		return
	}

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
