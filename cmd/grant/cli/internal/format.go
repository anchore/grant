package internal

import "github.com/google/uuid"

type Format string

const (
	JSON  Format = "json"
	Table Format = "table"
)

var ValidFormats = []Format{JSON, Table}

// ValidateFormat returns a valid format or the default format if the given format is invalid
func ValidateFormat(f Format) Format {
	switch f {
	case "json":
		return JSON
	case "table":
		return Table
	default:
		return Table
	}
}

func NewReportID() string {
	return uuid.Must(uuid.NewRandom()).String()
}
