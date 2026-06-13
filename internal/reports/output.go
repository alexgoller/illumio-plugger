package reports

import "context"

// Output is the interface that all output drivers implement.
type Output interface {
	Name() string
	Type() string
	Send(ctx context.Context, report *Report) error
	SendBatch(ctx context.Context, reports []*Report) error
}
