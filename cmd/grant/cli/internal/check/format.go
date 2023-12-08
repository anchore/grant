package check

type Format string

const (
	JSON  Format = "json"
	Table Format = "table"
)

// validFormat returns a valid format or the default format if the given format is invalid
func validateFormat(f Format) Format {
	switch f {
	case "json":
		return JSON
	case "table":
		return Table
	default:
		return Table
	}
}
