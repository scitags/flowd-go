package prometheus

import (
	"reflect"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestReflection(t *testing.T) {
	x := newMetrics()

	v := reflect.ValueOf(*x)

	for i := 0; i < v.NumField(); i++ {
		vv := v.Field(i).Interface()
		_, ok := vv.(prometheus.Collector)
		if !ok {
			t.Errorf("error casting the interface for %d", i)
		}
	}
}
