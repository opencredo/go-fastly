package fastly

import (
	"fmt"
	"reflect"
	"strconv"

	"github.com/google/jsonapi"
)

type WAFVersion struct {
	ID                               string `jsonapi:"primary,waf_firewall_version"`
	Number                           int    `jsonapi:"attr,number"`
	Active                           bool   `jsonapi:"attr,active"`
	Locked                           bool   `jsonapi:"attr,locked"`
	CRSValidateUTF8Encoding          bool   `jsonapi:"attr,crs_validate_utf8_encoding"`
	Comment                          string `jsonapi:"attr,comment"`
	Error                            string `jsonapi:"attr,error"`
	DeployedAt                       string `jsonapi:"attr,deployed_at"`
	AllowedHTTPVersions              string `jsonapi:"attr,allowed_http_versions"`
	AllowedMethods                   string `jsonapi:"attr,allowed_methods"`
	AllowedRequestContentType        string `jsonapi:"attr,allowed_request_content_type"`
	AllowedRequestContentTypeCharset string `jsonapi:"attr,allowed_request_content_type_charset"`
	HighRiskCountryCodes             string `jsonapi:"attr,high_risk_country_codes"`
	RestrictedExtensions             string `jsonapi:"attr,restricted_extensions"`
	RestrictedHeaders                string `jsonapi:"attr,restricted_headers"`
	CreatedAt                        string `jsonapi:"attr,created_at"`
	UpdatedAt                        string `jsonapi:"attr,updated_at"`
	ArgLength                        int    `jsonapi:"attr,arg_length"`
	ArgNameLength                    int    `jsonapi:"attr,arg_name_length"`
	CombinedFileSizes                int    `jsonapi:"attr,combined_file_sizes"`
	CriticalAnomalyScore             int    `jsonapi:"attr,critical_anomaly_score"`
	ErrorAnomalyScore                int    `jsonapi:"attr,error_anomaly_score"`
	HTTPViolationScoreThreshold      int    `jsonapi:"attr,http_violation_score_threshold"`
	InboundAnomalyScoreThreshold     int    `jsonapi:"attr,inbound_anomaly_score_threshold"`
	LFIScoreThreshold                int    `jsonapi:"attr,lfi_score_threshold"`
	MaxFileSize                      int    `jsonapi:"attr,max_file_size"`
	MaxNumArgs                       int    `jsonapi:"attr,max_num_args"`
	NoticeAnomalyScore               int    `jsonapi:"attr,notice_anomaly_score"`
	ParanoiaLevel                    int    `jsonapi:"attr,paranoia_level"`
	PHPInjectionScoreThreshold       int    `jsonapi:"attr,php_injection_score_threshold"`
	RCEScoreThreshold                int    `jsonapi:"attr,rce_score_threshold"`
	RFIScoreThreshold                int    `jsonapi:"attr,rfi_score_threshold"`
	SessionFixationScoreThreshold    int    `jsonapi:"attr,session_fixation_score_threshold"`
	SQLInjectionScoreThreshold       int    `jsonapi:"attr,sql_injection_score_threshold"`
	TotalArgLength                   int    `jsonapi:"attr,total_arg_length"`
	WarningAnomalyScore              int    `jsonapi:"attr,warning_anomaly_score"`
	XSSScoreThreshold                int    `jsonapi:"attr,xss_score_threshold"`
	ActiveRulesTrustwaveLogCount     int    `jsonapi:"attr,active_rules_trustwave_log_count"`
	ActiveRulesTrustwaveBlockCount   int    `jsonapi:"attr,active_rules_trustwave_block_count"`
	ActiveRulesFastlyLogCount        int    `jsonapi:"attr,active_rules_fastly_log_count"`
	ActiveRulesFastlyBlockCount      int    `jsonapi:"attr,active_rules_fastly_block_count"`
	ActiveRulesOWASPLogCount         int    `jsonapi:"attr,active_rules_owasp_log_count"`
	ActiveRulesOWASPBlockCount       int    `jsonapi:"attr,active_rules_owasp_block_count"`
}

type ListWAFVersionsInput struct {
	// The firewall id
	WAFID string
	// Limit the number of returned
	PageSize int
	// Request a specific page of firewalls.
	PageNumber int
	// Include relationships. Optional, comma-separated values. Permitted values: waf_firewall_versions.
	Include string
}

func (i *ListWAFVersionsInput) formatFilters() map[string]string {

	result := map[string]string{}
	pairings := map[string]interface{}{
		"page[size]":   i.PageSize,
		"page[number]": i.PageNumber,
		"include":      i.Include,
	}

	for key, value := range pairings {
		switch t := reflect.TypeOf(value).String(); t {
		case "string":
			if value != "" {
				result[key] = value.(string)
			}
		case "int":
			if value != 0 {
				result[key] = strconv.Itoa(value.(int))
			}
		}
	}
	return result
}

func (c *Client) ListWAFVersions(i *ListWAFVersionsInput) ([]*WAFVersion, error) {
	
	if i.WAFID == "" {
		return nil, ErrMissingWAFID
	}

	path := fmt.Sprintf("/waf/firewalls/%s/versions", i.WAFID)
	resp, err := c.Get(path, &RequestOptions{
		Params: i.formatFilters(),
	})
	if err != nil {
		return nil, err
	}

	data, err := jsonapi.UnmarshalManyPayload(resp.Body, wafType)
	if err != nil {
		return nil, err
	}

	wafs := make([]*WAFVersion, len(data))
	for i := range data {
		typed, ok := data[i].(*WAFVersion)
		if !ok {
			return nil, fmt.Errorf("got back a non-WAFVersion response")
		}
		wafs[i] = typed
	}
	return wafs, nil
}
