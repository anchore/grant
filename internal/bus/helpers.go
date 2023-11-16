package bus

import (
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/clio"
	"github.com/anchore/grant/event"
	"github.com/anchore/grant/internal/redact"
)

func Exit() {
	Publish(clio.ExitEvent(false))
}

func ExitWithInterrupt() {
	Publish(clio.ExitEvent(true))
}

func Report(report string) {
	if len(report) == 0 {
		return
	}
	report = redact.Apply(report)
	Publish(partybus.Event{
		Type:  event.CLIReport,
		Value: report,
	})
}

func Notify(message string) {
	Publish(partybus.Event{
		Type:  event.CLINotification,
		Value: message,
	})
}

func PublishTask(titles event.Title, context string, total int) *event.ManualStagedProgress {
	prog := &event.ManualStagedProgress{
		Manual:      progress.NewManual(int64(total)),
		AtomicStage: progress.NewAtomicStage(""),
	}

	Publish(partybus.Event{
		Type: event.TaskStartedEvent,
		Source: event.Task{
			Title:   titles,
			Context: context,
		},
		Value: progress.StagedProgressable(prog),
	})

	return prog
}
