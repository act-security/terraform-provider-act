package client

import (
	"net/http"
	"reflect"
	"testing"
)

func TestNewAPIError(t *testing.T) {
	got := newAPIError(http.StatusForbidden, []byte(`{"error":{"code":"feature_disabled","message":"off","requestId":"req_1","retryable":false}}`))
	want := &APIError{Status: 403, Code: "feature_disabled", Message: "off", RequestID: "req_1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("newAPIError = %+v, want %+v", got, want)
	}
	if got.Error() != "Act API returned 403 feature_disabled: off (request req_1)" {
		t.Fatalf("Error() = %q", got.Error())
	}

	conflict := newAPIError(http.StatusConflict, []byte(`{"error":{"code":"already_exists","message":"exists","requestId":"req_2","retryable":false,"details":{"integrationId":"abc"}}}`))
	if conflict.Detail("integrationId") != "abc" || conflict.Detail("missing") != "" {
		t.Fatalf("Detail() on %+v", conflict)
	}

	plain := newAPIError(http.StatusBadGateway, []byte("<html>bad gateway</html>"))
	if plain.Code != "Bad Gateway" || plain.Message != "" {
		t.Fatalf("newAPIError for a non-envelope body = %+v", plain)
	}
}
