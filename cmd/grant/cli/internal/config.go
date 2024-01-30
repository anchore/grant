package internal

// TODO: osi approved filter
// TODO: non spdx filter
// TODO: packages no licenses
// TODO: licenses no packages

type ReportOptions struct {
	Format       Format
	ShowPackages bool
	CheckNonSPDX bool
	OsiApproved  bool
}
