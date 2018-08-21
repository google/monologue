package monitor

import (
	"net/http"
	"testing"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-monitor/client"
	"github.com/google/go-cmp/cmp"
)

func TestCreateAPICall(t *testing.T) {
	pilotGetSTH := "https://ct.googleapis.com/pilot/ct/v1/get-sth"

	tests := []struct {
		name     string
		endpoint ct.APIEndpoint
		httpData *client.HTTPData
		err      error
		want     *APICall
	}{
		{
			name:     "nil httpData",
			endpoint: ct.GetSTHStr,
			err:      &client.NilResponseError{URL: pilotGetSTH},
			want: &APICall{
				Endpoint: ct.GetSTHStr,
				Err:      &client.NilResponseError{URL: pilotGetSTH},
			},
		},
		{
			name:     "no error",
			endpoint: ct.GetSTHStr,
			httpData: &client.HTTPData{
				Timing: client.Timing{
					Start: time.Date(2018, time.August, 21, 14, 12, 0, 0, time.UTC),
					End:   time.Date(2018, time.August, 21, 14, 14, 0, 0, time.UTC),
				},
				Response: &http.Response{StatusCode: http.StatusOK},
				Body:     []byte("some bytes"),
			},
			want: &APICall{
				Start:    time.Date(2018, time.August, 21, 14, 12, 0, 0, time.UTC),
				End:      time.Date(2018, time.August, 21, 14, 14, 0, 0, time.UTC),
				Endpoint: ct.GetSTHStr,
				Response: &http.Response{StatusCode: http.StatusOK},
				Body:     []byte("some bytes"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := CreateAPICall(test.endpoint, test.httpData, test.err)
			if diff := cmp.Diff(got, test.want); diff != "" {
				t.Errorf("CreateAPICall(): diff: (-got +want)\n%s", diff)
			}
		})
	}
}
