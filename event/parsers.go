package event

import (
	"fmt"

	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
)

type ErrBadPayload struct {
	Type  partybus.EventType
	Field string
	Value interface{}
}

func (e *ErrBadPayload) Error() string {
	return fmt.Sprintf("event='%s' has bad event payload field='%v': '%+v'", string(e.Type), e.Field, e.Value)
}

func newPayloadErr(t partybus.EventType, field string, value interface{}) error {
	return &ErrBadPayload{
		Type:  t,
		Field: field,
		Value: value,
	}
}

func checkEventType(actual, expected partybus.EventType) error {
	if actual != expected {
		return newPayloadErr(expected, "Type", actual)
	}
	return nil
}

func ParseCheckCommandStarted(e partybus.Event) ([]string, progress.StagedProgressable, error) {
	if err := checkEventType(e.Type, CLICheckCmdStarted); err != nil {
		return nil, nil, err
	}

	return parseSourcesAndStagedProgressable(e)
}

func parseSourcesAndStagedProgressable(e partybus.Event) ([]string, progress.StagedProgressable, error) {
	sources, ok := e.Source.([]string)
	if !ok {
		return nil, nil, newPayloadErr(e.Type, "Source", e.Source)
	}

	prog, ok := e.Value.(progress.StagedProgressable)
	if !ok {
		return nil, nil, newPayloadErr(e.Type, "Value", e.Value)
	}

	return sources, prog, nil
}

func ParseCLIReport(e partybus.Event) (string, string, error) {
	if err := checkEventType(e.Type, CLIReport); err != nil {
		return "", "", err
	}

	context, ok := e.Source.(string)
	if !ok {
		// this is optional
		context = ""
	}

	report, ok := e.Value.(string)
	if !ok {
		return "", "", newPayloadErr(e.Type, "Value", e.Value)
	}

	return context, report, nil
}

func ParseCLINotification(e partybus.Event) (string, string, error) {
	if err := checkEventType(e.Type, CLINotification); err != nil {
		return "", "", err
	}

	context, ok := e.Source.(string)
	if !ok {
		// this is optional
		context = ""
	}

	notification, ok := e.Value.(string)
	if !ok {
		return "", "", newPayloadErr(e.Type, "Value", e.Value)
	}

	return context, notification, nil
}
