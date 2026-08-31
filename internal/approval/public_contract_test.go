package approval

import (
	"reflect"
	"testing"
)

func TestApprovalRequestDoesNotExposeLegacyClaimedState(t *testing.T) {
	if _, ok := reflect.TypeOf(Request{}).FieldByName("ClaimedAt"); ok {
		t.Fatal("Request still exposes legacy ClaimedAt field")
	}
}
