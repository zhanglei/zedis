package stor

import (
	"bytes"
	"errors"

	log "github.com/Sirupsen/logrus"
	"github.com/zero-os/0-stor/client"
	"github.com/zero-os/0-stor/client/metastor"
)

// package Errors
var (
	ErrNilStorClient = errors.New("Stor client was nil")
)

// Client defines the 0-stor client
type Client interface {
	Close()
	Read(key []byte) ([]byte, error)
	Write(key []byte, value []byte) error
	KeyExists(key []byte) (bool, error)
}

// StorClient implementation
type storClient struct {
	client *client.Client
}

// NewStor creates a new store connection
func NewStor(config client.Config) (*storClient, error) {

	cl, err := client.NewClientFromConfig(config, -1)
	if err != nil {
		return nil, err
	}

	return &storClient{
		client: cl,
	}, nil
}

// Close closes the stor
func (sc *storClient) Close() {
	if sc != nil {
		sc.client.Close()
	}
}

// Read reads from the stor
func (sc *storClient) Read(key []byte) ([]byte, error) {
	log.Debug("Reading from 0-stor...")
	w := bytes.Buffer{}
	defer log.Debug("Done reading from the 0-stor")
	err := sc.client.Read(key, &w)
	return w.Bytes(), err
}

// Write writes to the stor
func (sc *storClient) Write(key []byte, value []byte) error {
	log.Debug("Writing to 0-stor...")
	defer log.Debug("Done writing to the 0-stor")
	r := bytes.NewReader(value)
	_, err := sc.client.Write(key, r)
	return err
}

func (sc *storClient) KeyExists(key []byte) (bool, error) {
	log.Debug("Checking if key is in the 0-stor...")
	defer log.Debug("Done checking the 0-stor")

	w := devNull{}
	err := sc.client.Read(key, w)

	if err != nil {
		if err != metastor.ErrNotFound {
			return false, err
		}
		return false, nil
	}

	return true, nil
}

//devNull implements an io.Writer that does nothing
type devNull struct{}

func (dn devNull) Write(p []byte) (n int, err error) {
	return len(p), nil
}
