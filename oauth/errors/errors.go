package errors

import (
	"errors"
	"net/http"
)

type RestErr struct {
	Message string `json:"message"`
	Error   string `json:"error"`
	Status  int    `json:"status"`
}

func NewError(msg string) error {
	return errors.New(msg)
}

func NewBadRequestError(msg string) *RestErr {
	return &RestErr{
		Message: msg,
		Error:   "bad_request",
		Status:  http.StatusBadRequest,
	}
}

func NewNotFoundError(msg string) *RestErr {
	return &RestErr{
		Message: msg,
		Error:   "not_found",
		Status:  http.StatusNotFound,
	}
}

func NewInternalServerError(msg string) *RestErr {
	return &RestErr{
		Message: msg,
		Error:   "internal_server_error",
		Status:  http.StatusInternalServerError,
	}
}
