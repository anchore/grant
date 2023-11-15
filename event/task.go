package event

import "github.com/wagoodman/go-progress"

type Task struct {
	Title   Title
	Context string
}

type Title struct {
	Default      string
	WhileRunning string
	OnSuccess    string
	OnFail       string
}

type ManualStagedProgress struct {
	*progress.AtomicStage
	*progress.Manual
}
