package fastly

import (
	"reflect"
	"strconv"
	"testing"
)

func TestClient_WAF_Versions(t *testing.T) {
	t.Parallel()

	fixtureBase := "waf_versions/"

	testService := createTestService(t, fixtureBase+"create_service", "service")
	defer deleteTestService(t, fixtureBase+"delete_service", testService.ID)

	tv := createTestVersion(t, fixtureBase+"/version", testService.ID)

	var err error
	// Enable logging on the service - we cannot create wafs without logging
	// enabled
	record(t, fixtureBase+"/logging/create", func(c *Client) {
		_, err = c.CreateSyslog(&CreateSyslogInput{
			Service:       testService.ID,
			Version:       tv.Number,
			Name:          "test-syslog",
			Address:       "example.com",
			Hostname:      "example.com",
			Port:          1234,
			Token:         "abcd1234",
			Format:        "format",
			FormatVersion: 2,
			MessageType:   "classic",
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		record(t, fixtureBase+"/logging/cleanup", func(c *Client) {
			c.DeleteSyslog(&DeleteSyslogInput{
				Service: testService.ID,
				Version: tv.Number,
				Name:    "test-syslog",
			})
		})
	}()

	// Create a condition - we cannot create a waf without attaching a condition
	var condition *Condition
	record(t, fixtureBase+"/condition/create", func(c *Client) {
		condition, err = c.CreateCondition(&CreateConditionInput{
			Service:   testService.ID,
			Version:   tv.Number,
			Name:      "WAF_Prefetch",
			Statement: "req.url~+\"index.html\"",
			Type:      "PREFETCH", // This must be a prefetch condition
			Priority:  1,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		record(t, fixtureBase+"/condition/cleanup", func(c *Client) {
			c.DeleteCondition(&DeleteConditionInput{
				Service: testService.ID,
				Version: tv.Number,
				Name:    condition.Name,
			})
		})
	}()

	// Create a response object
	var ro *ResponseObject
	record(t, fixtureBase+"/response_object/create", func(c *Client) {
		ro, err = c.CreateResponseObject(&CreateResponseObjectInput{
			Service:     testService.ID,
			Version:     tv.Number,
			Name:        "WAf_Response",
			Status:      200,
			Response:    "Ok",
			Content:     "abcd",
			ContentType: "text/plain",
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		record(t, fixtureBase+"/response_object/cleanup", func(c *Client) {
			c.DeleteResponseObject(&DeleteResponseObjectInput{
				Service: testService.ID,
				Version: tv.Number,
				Name:    ro.Name,
			})
		})
	}()

	var waf *WAF
	record(t, fixtureBase+"/create", func(c *Client) {
		waf, err = c.CreateWAF(&CreateWAFInput{
			Service:           testService.ID,
			Version:           strconv.Itoa(tv.Number),
			PrefetchCondition: condition.Name,
			Response:          ro.Name,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		record(t, fixtureBase+"/cleanup", func(c *Client) {
			c.DeleteWAF(&DeleteWAFInput{
				Version: strconv.Itoa(tv.Number),
				ID:      waf.ID,
			})
		})
	}()

	var wafVerResp *WAFVersionResponse
	record(t, fixtureBase+"/list", func(c *Client) {
		wafVerResp, err = c.ListWAFVersions(&ListWAFVersionsInput{
			WAFID:      waf.ID,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(wafVerResp.Items) != 1 {
		t.Errorf("expected 1 waf: got %d", len(wafVerResp.Items))
	}

	record(t, fixtureBase+"/deploy", func(c *Client) {
		err = c.DeployWAFVersion(&DeployWAFVersionInput{
			WAFID:      waf.ID,
			WAFVersion: 1,
		})
	})
	if err != nil {
		t.Fatal(err)
	}

	var wafVer *WAFVersion
	record(t, fixtureBase+"/clone", func(c *Client) {
		wafVer, err = c.CloneWAFVersion(&CloneWAFVersionInput{
			WAFID:      waf.ID,
			WAFVersion: 1,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if wafVer == nil {
		t.Errorf("expected 1 waf: got %d", len(wafVerResp.Items))
	}

	record(t, fixtureBase+"/get", func(c *Client) {
		wafVer, err = c.GetWAFVersion(&GetWAFVersionInput{
			WAFID:      waf.ID,
			WAFVersion: 2,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if wafVer == nil {
		t.Error("expected waf, got nil" )
	}

	threshold := 80
	record(t, fixtureBase+"/update", func(c *Client) {
		wafVer, err = c.UpdateWAFVersion(&UpdateWAFVersionInput{
			WAFID:      waf.ID,
			WAFVersion: 2,
			ID:   wafVer.ID,
			HTTPViolationScoreThreshold: threshold,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if wafVer == nil {
		t.Error("expected waf, got nil" )
	}
	if wafVer.HTTPViolationScoreThreshold != threshold {
		t.Errorf("expected %d waf: got %d", threshold, wafVer.HTTPViolationScoreThreshold)
	}

	record(t, fixtureBase+"/lock", func(c *Client) {
		wafVer, err = c.LockWAFVersion(&LockWAFVersionInput{
			WAFID:      waf.ID,
			WAFVersion: 2,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if wafVer == nil {
		t.Error("expected waf, got nil" )
	}
	if !wafVer.Locked {
		t.Errorf("expected locked = true waf: got locked == %v", wafVer.Locked)
	}

	record(t, fixtureBase+"/list_all", func(c *Client) {
		wafVerResp, err = c.ListAllWAFVersions(&ListWAFVersionsInput{
			WAFID:      waf.ID,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(wafVerResp.Items) != 2 {
		t.Errorf("expected 2 waf: got %d", len(wafVerResp.Items))
	}
}

func TestClient_listWAFVersions_formatFilters(t *testing.T) {
	cases := []struct {
		remote *ListWAFVersionsInput
		local  map[string]string
	}{
		{
			remote: &ListWAFVersionsInput{
				PageSize:      2,
				PageNumber:    2,
				Include:       "included",
			},
			local: map[string]string{
				"page[size]":                     "2",
				"page[number]":                   "2",
				"include":                        "included",
			},
		},
	}
	for _, c := range cases {
		out := c.remote.formatFilters()
		if !reflect.DeepEqual(out, c.local) {
			t.Fatalf("Error matching:\nexpected: %#v\n     got: %#v", c.local, out)
		}
	}
}

func TestClient_ListWAFVersions_validation(t *testing.T) {
	var err error
	_, err = testClient.ListWAFVersions(&ListWAFVersionsInput{
		WAFID: "",
	})
	if err != ErrMissingWAFID {
		t.Errorf("bad error: %s", err)
	}
}


func TestClient_ListAllWAFVersions_validation(t *testing.T) {
	var err error
	_, err = testClient.ListAllWAFVersions(&ListWAFVersionsInput{
		WAFID: "",
	})
	if err != ErrMissingWAFID {
		t.Errorf("bad error: %s", err)
	}
}

func TestClient_GetWAFVersion_validation(t *testing.T) {
	var err error
	_, err = testClient.GetWAFVersion(&GetWAFVersionInput{
		WAFID: "",
	})
	if err != ErrMissingWAFID {
		t.Errorf("bad error: %s", err)
	}

	_, err = testClient.GetWAFVersion(&GetWAFVersionInput{
		WAFID: "1",
		WAFVersion: 0,
	})
	if err != ErrMissingWAFNumber {
		t.Errorf("bad error: %s", err)
	}
}

func TestClient_UpdateWAFVersion_validation(t *testing.T) {
	var err error
	_, err = testClient.UpdateWAFVersion(&UpdateWAFVersionInput{
		WAFID: "",
	})
	if err != ErrMissingWAFID {
		t.Errorf("bad error: %s", err)
	}

	_, err = testClient.UpdateWAFVersion(&UpdateWAFVersionInput{
		WAFID: "1",
		WAFVersion: 0,
	})
	if err != ErrMissingWAFNumber {
		t.Errorf("bad error: %s", err)
	}

	_, err = testClient.UpdateWAFVersion(&UpdateWAFVersionInput{
		WAFID: "1",
		WAFVersion: 1,
		ID: "",
	})
	if err != ErrMissingWAFVersionID {
		t.Errorf("bad error: %s", err)
	}
}

func TestClient_LockWAFVersion_validation(t *testing.T) {
	var err error
	_, err = testClient.LockWAFVersion(&LockWAFVersionInput{
		WAFID: "",
	})
	if err != ErrMissingWAFID {
		t.Errorf("bad error: %s", err)
	}

	_, err = testClient.LockWAFVersion(&LockWAFVersionInput{
		WAFID: "1",
		WAFVersion: 0,
	})
	if err != ErrMissingWAFNumber {
		t.Errorf("bad error: %s", err)
	}
}

func TestClient_CloneWAFVersion_validation(t *testing.T) {
	var err error
	_, err = testClient.CloneWAFVersion(&CloneWAFVersionInput{
		WAFID: "",
	})
	if err != ErrMissingWAFID {
		t.Errorf("bad error: %s", err)
	}

	_, err = testClient.CloneWAFVersion(&CloneWAFVersionInput{
		WAFID: "1",
		WAFVersion: 0,
	})
	if err != ErrMissingWAFNumber {
		t.Errorf("bad error: %s", err)
	}
}

func TestClient_DeployWAFVersion_validation(t *testing.T) {
	var err error
	if err = testClient.DeployWAFVersion(&DeployWAFVersionInput{
		WAFID: "",
	}); err != ErrMissingWAFID {
		t.Errorf("bad error: %s", err)
	}

	if err = testClient.DeployWAFVersion(&DeployWAFVersionInput{
		WAFID: "1",
		WAFVersion: 0,
	}); err != ErrMissingWAFNumber {
		t.Errorf("bad error: %s", err)
	}
}





