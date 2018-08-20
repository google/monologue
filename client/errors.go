package client

import (
	"fmt"
	"reflect"
)

// GetError for if http.Client.Get() fails.
type GetError struct {
	URL string
	Err error
}

func (e *GetError) Error() string {
	return fmt.Sprintf("GET %s: %v", e.URL, e.Err)
}

// NilResponseError for if http.Client.Get() returns a nil response, but no
// error.
type NilResponseError struct {
	URL string
}

func (e *NilResponseError) Error() string {
	return fmt.Sprintf("nil response from %s", e.URL)
}

// BodyReadError for if reading the body of an http.Response fails.
type BodyReadError struct {
	URL string
	Err error
}

func (e *BodyReadError) Error() string {
	return fmt.Sprintf("error reading body from %s: %s", e.URL, e.Err)
}

// HTTPStatusError for if the status code of an HTTP response is not 200.
type HTTPStatusError struct {
	StatusCode int
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("HTTP status code: %d, want 200", e.StatusCode)
}

// JSONParseError for if JSON fails to parse.
type JSONParseError struct {
	Data []byte
	Err  error
}

func (e *JSONParseError) Error() string {
	return fmt.Sprintf("json.Unmarshal(): %s", e.Err)
}

// ResponseToStructError for if conversion from response type to ct type fails.
type ResponseToStructError struct {
	From reflect.Type
	To   reflect.Type
	Err  error
}

func (e *ResponseToStructError) Error() string {
	return fmt.Sprintf("converting %v to %v: %s", e.From, e.To, e.Err)
}
