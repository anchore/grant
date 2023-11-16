package event

import "github.com/wagoodman/go-partybus"

const (
	typePrefix    = "grant"
	cliTypePrefix = typePrefix + "-cli"

	// Events from the grant library

	// TaskStartedEvent is a generic, monitorable partybus event that occurs when a task has begun
	TaskStartedEvent partybus.EventType = typePrefix + "-task"
	// Events exclusively for the CLI

	// CLICheckCmdStarted is a partybus event that occurs when the check cli command has begun
	CLICheckCmdStarted partybus.EventType = cliTypePrefix + "-check-cmd-started"

	// CLIReport is a partybus event that occurs when the cli is ready to generate a report
	CLIReport partybus.EventType = cliTypePrefix + "-report"

	// CLINotification is a partybus event that occurs when auxiliary information is ready for presentation to stderr
	CLINotification partybus.EventType = cliTypePrefix + "-notification"
)
