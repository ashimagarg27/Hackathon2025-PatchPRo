package loader

import (
	"encoding/json"
	"os"
	"patchpro/pkg/models"
)

// LoadRawFeed reads the JSON file at path and unmarshals into RawFeed.
func LoadRawFeed(path string) (models.RawFeed, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var rf models.RawFeed
	if err := json.Unmarshal(b, &rf); err != nil {
		return nil, err
	}

	return rf, nil
}
