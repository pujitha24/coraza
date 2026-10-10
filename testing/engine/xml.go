// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// XML currently disabled on TinyGo
//go:build !tinygo

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "jptosso",
		Description: "Test if the body processors work",
		Enabled:     true,
		Name:        "postxml.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "postxml",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/index.php?t1=aaa&t2=bbb&t3=ccc",
							Method: "POST",
							Headers: map[string]string{
								"content-type": "application/xml",
							},
							Data: `<?xml version="1.0"?><xml><Cs7QAF attribute_name="attribute_value">test123</Cs7QAF></xml>`,
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{101, 102, 500, 600, 601},
							NonTriggeredRules: []int{103, 602},
							Headers: map[string]string{
								"Content-Type": "application/xml",
							},
							Data: `<?xml version="1.0"?><xml><Cs7QAF attribute_name="attribute_value">test123</Cs7QAF></xml>`,
						},
					},
				},
			},
		},
	},
	Rules: `
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType application/xml
SecRule REQUEST_HEADERS:content-type "application/xml" "id: 100, phase:1, pass, log, ctl:requestBodyProcessor=XML"
SecRule REQBODY_PROCESSOR "XML" "id: 101,phase:2,log,block"
SecRule XML:/*|XML://@* "test123" "id:102, phase:2,log,block"
#REQUEST_BODY must be empty for XML body processor
SecRule XML:/* "test123" "id:500, log"
SecRule XML://@* "attribute_value" "id:501, log"
SecRule RESPONSE_HEADERS:content-type "application/xml" "id:600, phase:3, pass, log, ctl:responseBodyProcessor=XML"
SecRule RESPONSE_XML:/* "test123" "id:601, phase:4, log, block"
SecRule RESPONSE_XML:/* "no_such_value" "id:602, phase:4, log, block"
`,
})
