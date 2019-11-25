package fastly

import (
	"reflect"
	"strconv"
	"testing"
)

func TestClient_WAF_Versions(t *testing.T) {
	t.Parallel()

	fixtureBase := "waf_versions/"

	testService := createTestService(t, fixtureBase+"service/create", "service")
	defer deleteTestService(t, fixtureBase+"/service/delete", testService.ID)

	tv := createTestVersion(t, fixtureBase+"/service/version", testService.ID)

	createTestLogging(t, fixtureBase+"/logging/create", testService.ID, tv.Number)
	defer deleteTestLogging(t, fixtureBase+"/logging/delete", testService.ID, tv.Number)

	prefetch := "WAF_Prefetch"
	condition := createTestWAFCondition(t, fixtureBase+"/condition/create", testService.ID, prefetch, tv.Number)
	defer deleteTestWAFCondition(t, fixtureBase+"/condition/delete", testService.ID, prefetch, tv.Number)

	responseName := "WAf_Response"
	ro := createTestResponseObject(t, fixtureBase+"/response_object/create", testService.ID, responseName, tv.Number)
	defer deleteTestResponseObject(t, fixtureBase+"/response_object/delete", testService.ID, responseName, tv.Number)

	var err error
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
			if err := c.DeleteWAF(&DeleteWAFInput{
				Version: strconv.Itoa(tv.Number),
				ID:      waf.ID,
			}); err != nil {
				t.Fatal(err)
			}
		})
	}()

	var wafVerResp *WAFVersionResponse
	record(t, fixtureBase+"/list", func(c *Client) {
		wafVerResp, err = c.ListWAFVersions(&ListWAFVersionsInput{
			WAFID: waf.ID,
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
		t.Error("expected waf, got nil")
	}

	threshold := 80
	record(t, fixtureBase+"/update", func(c *Client) {
		wafVer, err = c.UpdateWAFVersion(&UpdateWAFVersionInput{
			WAFID:                       waf.ID,
			WAFVersion:                  2,
			ID:                          wafVer.ID,
			HTTPViolationScoreThreshold: threshold,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if wafVer == nil {
		t.Error("expected waf, got nil")
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
		t.Error("expected waf, got nil")
	}
	if !wafVer.Locked {
		t.Errorf("expected locked = true waf: got locked == %v", wafVer.Locked)
	}

	record(t, fixtureBase+"/list_all", func(c *Client) {
		wafVerResp, err = c.ListAllWAFVersions(&ListWAFVersionsInput{
			WAFID: waf.ID,
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
				PageSize:   2,
				PageNumber: 2,
				Include:    "included",
			},
			local: map[string]string{
				"page[size]":   "2",
				"page[number]": "2",
				"include":      "included",
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
		WAFID:      "1",
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
		WAFID:      "1",
		WAFVersion: 0,
	})
	if err != ErrMissingWAFNumber {
		t.Errorf("bad error: %s", err)
	}

	_, err = testClient.UpdateWAFVersion(&UpdateWAFVersionInput{
		WAFID:      "1",
		WAFVersion: 1,
		ID:         "",
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
		WAFID:      "1",
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
		WAFID:      "1",
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
		WAFID:      "1",
		WAFVersion: 0,
	}); err != ErrMissingWAFNumber {
		t.Errorf("bad error: %s", err)
	}
}
