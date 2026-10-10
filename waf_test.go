// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/internal/corazawaf"
	"github.com/corazawaf/coraza/v3/types"
)

// wafWithRules mirrors experimental.WAFWithRules for testing without import cycle.
type wafWithRules interface {
	RulesCount() int
}

func TestRequestBodyLimit(t *testing.T) {
	testCases := map[string]struct {
		expectedErr   error
		limit         int
		inMemoryLimit int
	}{
		"empty limit": {
			limit:         0,
			inMemoryLimit: 2,
			expectedErr:   errors.New("request body limit should be bigger than 0"),
		},
		"empty memory limit": {
			limit:         2,
			inMemoryLimit: 0,
			expectedErr:   errors.New("request body memory limit should be bigger than 0"),
		},
		"memory limit bigger than limit": {
			limit:         5,
			inMemoryLimit: 9,
			expectedErr:   errors.New("request body limit should be at least the memory limit"),
		},
		"limit bigger than the hard limit": {
			limit:       1073741825,
			expectedErr: errors.New("request body limit should be at most 1GiB"),
		},
		"right limits": {
			limit:         100,
			inMemoryLimit: 50,
		},
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			cfg := NewWAFConfig().(*wafConfig)
			cfg.requestBodyLimit = &tCase.limit
			cfg.requestBodyInMemoryLimit = &tCase.inMemoryLimit

			_, err := NewWAF(cfg)
			if tCase.expectedErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %s", err.Error())
				}
			} else {
				if err == nil {
					t.Fatal("expected error")
				}

				if want, have := tCase.expectedErr, err; want.Error() != have.Error() {
					t.Fatalf("unexpected error: want %q, have %q", want, have)
				}
			}
		})
	}
}

func TestResponseBodyLimit(t *testing.T) {
	testCases := map[string]struct {
		expectedErr error
		limit       int
	}{
		"empty limit": {
			limit:       0,
			expectedErr: errors.New("response body limit should be bigger than 0"),
		},
		"limit bigger than the hard limit": {
			limit:       1073741825,
			expectedErr: errors.New("response body limit should be at most 1GiB"),
		},
		"right limit": {
			limit: 100,
		},
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			cfg := NewWAFConfig().(*wafConfig)
			cfg.responseBodyLimit = &tCase.limit

			_, err := NewWAF(cfg)
			if tCase.expectedErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %s", err.Error())
				}
			} else {
				if err == nil {
					t.Fatal("expected error")
				}

				if want, have := tCase.expectedErr, err; want.Error() != have.Error() {
					t.Fatalf("unexpected error: want %q, have %q", want, have)
				}
			}
		})
	}
}

type testAuditLogWriter struct {
	plugintypes.AuditLogWriter
}

func (*testAuditLogWriter) Init(plugintypes.AuditLogConfig) error {
	return nil
}

func TestPopulateAuditLog(t *testing.T) {
	writer := &testAuditLogWriter{}

	testCases := map[string]struct {
		config *wafConfig
		check  func(*testing.T, *corazawaf.WAF)
	}{
		"empty config": {
			config: &wafConfig{},
			check:  func(*testing.T, *corazawaf.WAF) {},
		},
		"with relevant only": {
			config: &wafConfig{
				auditLog: &auditLogConfig{
					relevantOnly: true,
				},
			},
			check: func(t *testing.T, waf *corazawaf.WAF) {
				if waf.AuditEngine != types.AuditEngineRelevantOnly {
					t.Fatal("expected AuditLogRelevantOnly to be true")
				}
			},
		},
		"with parts": {
			config: &wafConfig{
				auditLog: &auditLogConfig{
					parts: []types.AuditLogPart{
						types.AuditLogPartRequestHeaders,
						types.AuditLogPartResponseBody,
					},
				},
			},
			check: func(t *testing.T, waf *corazawaf.WAF) {
				if want, have := []types.AuditLogPart{
					types.AuditLogPartRequestHeaders,
					types.AuditLogPartResponseBody,
				}, waf.AuditLogParts; len(want) != len(have) {
					t.Fatalf("unexpected AuditLogParts: want %v, have %v", want, have)
				}
			},
		},
		"with audit log writer": {
			config: &wafConfig{
				auditLog: &auditLogConfig{writer: writer},
			},
			check: func(t *testing.T, waf *corazawaf.WAF) {
				if reflect.DeepEqual(waf.AuditLogWriter(), &writer) {
					t.Fatal("expected AuditLogWriter to be set")
				}
			},
		},
	}

	for name, tCase := range testCases {
		t.Run(name, func(t *testing.T) {
			waf := &corazawaf.WAF{}
			populateAuditLog(waf, tCase.config)
			tCase.check(t, waf)
		})
	}
}

func TestDetectionOnlyEnforcesProcessPartialBodyLimitActions(t *testing.T) {
	waf, err := NewWAF(NewWAFConfig().WithDirectives(`
		SecRuleEngine DetectionOnly
		SecRequestBodyAccess On
		SecRequestBodyLimitAction Reject
		SecResponseBodyAccess On
		SecResponseBodyLimitAction Reject
	`))
	if err != nil {
		t.Fatal(err)
	}

	w := waf.(wafWrapper).waf
	if w.RequestBodyLimitAction != types.BodyLimitActionProcessPartial {
		t.Fatalf("expected RequestBodyLimitAction to be ProcessPartial in DetectionOnly mode, got %v", w.RequestBodyLimitAction)
	}
	if w.ResponseBodyLimitAction != types.BodyLimitActionProcessPartial {
		t.Fatalf("expected ResponseBodyLimitAction to be ProcessPartial in DetectionOnly mode, got %v", w.ResponseBodyLimitAction)
	}
}

func TestRulesCount(t *testing.T) {
	waf, err := NewWAF(NewWAFConfig())
	if err != nil {
		t.Fatal(err)
	}

	rules, ok := waf.(wafWithRules)
	if !ok {
		t.Fatal("WAF does not implement WAFWithRules")
	}
	if rules.RulesCount() != 0 {
		t.Fatalf("expected 0 rules, got %d", rules.RulesCount())
	}

	waf, err = NewWAF(NewWAFConfig().
		WithDirectives(`SecRule REMOTE_ADDR "127.0.0.1" "id:1,phase:1,deny,status:403"`).
		WithDirectives(`SecRule REQUEST_URI "/test" "id:2,phase:1,deny,status:403"`))
	if err != nil {
		t.Fatal(err)
	}

	rules, ok = waf.(wafWithRules)
	if !ok {
		t.Fatal("WAF does not implement WAFWithRules")
	}
	if rules.RulesCount() != 2 {
		t.Fatalf("expected 2 rules, got %d", rules.RulesCount())
	}
}

// Concurrency cannot be expressed as an engine profile, which runs sequentially.
func TestConcurrentRuleRemoveTargetByID(t *testing.T) {
	// Rule 3 has three static exceptions (len 3, cap 4), so an append on a
	// copy of its Exceptions would write into the shared backing array.
	waf, err := NewWAF(NewWAFConfig().WithDirectives(`
SecRuleEngine On
SecRule REQUEST_URI "@beginsWith /alpha" "id:1,phase:1,pass,nolog,ctl:ruleRemoveTargetById=3;REQUEST_COOKIES:alpha"
SecRule REQUEST_URI "@beginsWith /beta" "id:2,phase:1,pass,nolog,ctl:ruleRemoveTargetById=3;REQUEST_COOKIES:beta"
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:a|!REQUEST_COOKIES:b|!REQUEST_COOKIES:c "@rx ." "id:3,phase:1,deny,status:403,log"
`))
	if err != nil {
		t.Fatal(err)
	}
	var blocked atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				name := []string{"alpha", "beta"}[(w+i)%2]
				tx := waf.NewTransaction()
				tx.ProcessURI("/"+name, "GET", "HTTP/1.1")
				tx.AddRequestHeader("Cookie", name+"=1")
				if tx.ProcessRequestHeaders() != nil {
					blocked.Add(1)
				}
				tx.ProcessLogging()
				_ = tx.Close()
			}
		}()
	}
	wg.Wait()
	if n := blocked.Load(); n > 0 {
		t.Errorf("%d requests were blocked by a target their own ctl removed", n)
	}
}
