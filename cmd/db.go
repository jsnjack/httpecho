package cmd

import (
	"fmt"
	"strconv"
)

// DB structure
// - bucket `storage` represents storage for key-value pairs (path -> responses)

var StorageBucket = []byte("storage")

// SaveRequest saves request to the storage
func SaveRequest(path string, dumpedRequest []byte) (uint64, error) {
	tx, err := DB.Begin(true) // Write transaction
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// Retrieve the storage bucket
	bucket := tx.Bucket(StorageBucket)
	if bucket == nil {
		return 0, fmt.Errorf("bucket %q not found", StorageBucket)
	}

	// Create a new bucket for the path
	pathBucket, err := bucket.CreateBucketIfNotExists([]byte(path))
	if err != nil {
		return 0, err
	}

	// Generate a new request ID
	reqID, err := pathBucket.NextSequence()
	if err != nil {
		return 0, err
	}

	// Save the request
	if err := pathBucket.Put([]byte(strconv.FormatUint(reqID, 10)), dumpedRequest); err != nil {
		return 0, err
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return reqID, nil
}

// GetRequest retrieves request from the storage
func GetRequest(path string, reqID uint64) ([]byte, error) {
	tx, err := DB.Begin(false) // Read transaction
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Retrieve the storage bucket
	bucket := tx.Bucket(StorageBucket)
	if bucket == nil {
		return nil, fmt.Errorf("bucket %q not found", StorageBucket)
	}

	// Retrieve the path bucket
	pathBucket := bucket.Bucket([]byte(path))
	if pathBucket == nil {
		return nil, fmt.Errorf("bucket %q not found", path)
	}

	// Retrieve the request
	dumpedRequest := pathBucket.Get([]byte(strconv.FormatUint(reqID, 10)))
	if dumpedRequest == nil {
		return nil, fmt.Errorf("request %d not found", reqID)
	}

	return dumpedRequest, nil
}

func GetAllRequestForPath(path string) (map[uint64]string, error) {
	tx, err := DB.Begin(false) // Read transaction
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// Retrieve the storage bucket
	bucket := tx.Bucket(StorageBucket)
	if bucket == nil {
		return nil, fmt.Errorf("bucket %q not found", StorageBucket)
	}

	// Retrieve the path bucket
	pathBucket := bucket.Bucket([]byte(path))
	if pathBucket == nil {
		return nil, fmt.Errorf("bucket %q not found", path)
	}

	requests := make(map[uint64]string)
	c := pathBucket.Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		reqID, err := strconv.ParseUint(string(k), 10, 64)
		if err != nil {
			return nil, err
		}
		requests[reqID] = string(v)
	}

	return requests, nil
}
