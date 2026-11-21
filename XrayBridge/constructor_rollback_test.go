//go:build hop_patched_core

package libXray

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type rollbackProbeKey struct{}

type rollbackProbe struct{ closed bool }

func (*rollbackProbe) Type() any      { return (*rollbackProbe)(nil) }
func (*rollbackProbe) Start() error   { return nil }
func (p *rollbackProbe) Close() error { p.closed = true; return nil }

func init() {
	common.Must(common.RegisterConfig((*wrapperspb.BoolValue)(nil), func(ctx context.Context, _ any) (any, error) {
		return ctx.Value(rollbackProbeKey{}).(*rollbackProbe), nil
	}))
}

func TestFailedConstructionClosesPreviouslyInstalledFeatures(t *testing.T) {
	probe := new(rollbackProbe)
	ctx := context.WithValue(context.Background(), rollbackProbeKey{}, probe)
	config := &core.Config{App: []*serial.TypedMessage{
		serial.ToTypedMessage(wrapperspb.Bool(true)),
		{Type: "hop.test.UnknownFeature"},
	}}
	if instance, err := core.NewWithContext(ctx, config); err == nil {
		instance.Close()
		t.Fatal("unexpected successful construction")
	}
	if !probe.closed {
		t.Fatal("failed construction retained a previously installed feature")
	}
}
