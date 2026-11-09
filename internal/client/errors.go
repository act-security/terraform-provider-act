package client

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/act-security/terraform-provider-act/internal/apigen"
)

type APIError struct {
	Status    int
	Code      string
	Message   string
	RequestID string
	Retryable bool
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("Act API returned %d %s", e.Status, e.Code)
	if e.Message != "" {
		msg += ": " + e.Message
	}
	if e.RequestID != "" {
		msg += " (request " + e.RequestID + ")"
	}
	return msg
}

func newAPIError(status int, body []byte) *APIError {
	var envelope apigen.ErrorEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil || envelope.Error.Code == "" {
		return &APIError{Status: status, Code: http.StatusText(status)}
	}
	return &APIError{
		Status:    status,
		Code:      string(envelope.Error.Code),
		Message:   envelope.Error.Message,
		RequestID: envelope.Error.RequestID,
		Retryable: envelope.Error.Retryable,
	}
}
