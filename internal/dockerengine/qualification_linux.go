//go:build linux && runnerd_qualification

package dockerengine

import (
	"context"
	"reflect"
	"sort"

	"github.com/moby/moby/client"
)

// QualificationDiff exports field names only, never environment values, raw
// inspect data or credentials. It cannot relax Inspect or authorize mutations.
func (e *Engine) QualificationDiff(ctx context.Context, id string, p Plan) []string {
	r, err := e.api.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil || r.Container.Config == nil || r.Container.HostConfig == nil || p.Config == nil || p.HostConfig == nil {
		return []string{"inspection-unavailable"}
	}
	c := r.Container
	result := []string{}
	for _, pair := range []struct {
		prefix         string
		actual, wanted any
	}{{"config", c.Config, p.Config}, {"host", c.HostConfig, p.HostConfig}} {
		a, b := reflect.ValueOf(pair.actual).Elem(), reflect.ValueOf(pair.wanted).Elem()
		for i := 0; i < a.NumField(); i++ {
			if !reflect.DeepEqual(a.Field(i).Interface(), b.Field(i).Interface()) {
				result = append(result, pair.prefix+"."+a.Type().Field(i).Name)
			}
		}
	}
	sort.Strings(result)
	return result
}
