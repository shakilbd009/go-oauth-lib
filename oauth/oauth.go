package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mercadolibre/golang-restclient/rest"
	"github.com/shakilbd009/go-oauth-lib/oauth/errors"
)

const (
	headerXPublic   = "X-Public"
	headerXClientID = "X-ClientID"
	headerXCallerID = "X-CallerID"

	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8082",
		Timeout: time.Millisecond * 200,
	}
)

type accessToken struct {
	Id       string `json:"id"`
	userId   int64  `json:"user_id"`
	clientId int64  `json:"client_id"`
}

type oauthInterface interface {
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetClientID(req *http.Request) int64 {

	if req == nil {
		return 0
	}
	clientID, err := strconv.ParseInt(req.Header.Get(headerXClientID), 10, 64)
	if err != nil {
		return 0
	}
	return clientID
}

func GetCallerID(req *http.Request) int64 {

	if req == nil {
		return 0
	}
	callerID, err := strconv.ParseInt(req.Header.Get(headerXCallerID), 10, 64)
	if err != nil {
		return 0
	}
	return callerID
}

func AuthenticateRequest(request *http.Request) *errors.RestErr {

	if request == nil {
		return nil
	}
	cleanRequest(request)
	accessToken := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessToken == "" {
		// return errors.NewBadRequestError("no access token given")
		return nil
	}
	at, err := getAccessToken(accessToken)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}
		return err
	}
	request.Header.Add(headerXClientID, fmt.Sprintf("%v", at.clientId))
	request.Header.Add(headerXCallerID, fmt.Sprintf("%v", at.userId))
	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientID)
	request.Header.Del(headerXCallerID)
}

func getAccessToken(at string) (*accessToken, *errors.RestErr) {

	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", at))
	if response == nil || response.Response == nil {
		return nil, errors.NewInternalServerError("invalid restclient response when trying to get access token")
	}
	if response.StatusCode > 299 {
		var restErr errors.RestErr
		if err := json.Unmarshal(response.Bytes(), &restErr); err != nil {
			return nil, errors.NewInternalServerError("invalid error interface when trying to unmarshal error msg")
		}
		return nil, &restErr
	}
	var access_token accessToken
	if err := json.Unmarshal(response.Bytes(), &access_token); err != nil {
		return nil, errors.NewInternalServerError("invalid error interface when trying to unmarshal error msg")
	}
	return &access_token, nil
}
