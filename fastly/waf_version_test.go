package fastly

import "testing"

func TestClient_ListWAFVersion_validation(t *testing.T) {
	var err error
	_, err = testClient.ListWAFVersions(&ListWAFVersionsInput{
		WAFID: "",
	})
	if err != ErrMissingWAFID {
		t.Errorf("bad error: %s", err)
	}

	_, err = testClient.ListWAFVersions(&ListWAFVersionsInput{
		WAFID: "",
	})
	if err != ErrMissingWAFID {
		t.Errorf("bad error: %s", err)
	}
}
