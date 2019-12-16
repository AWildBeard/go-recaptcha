// Package recaptcha handles reCaptcha (http://www.google.com/recaptcha) form submissions
//
// This package is designed to be called from within an HTTP server or web framework
// which offers reCaptcha form inputs and requires them to be evaluated for correctness
//
// Edit the recaptchaPrivateKey constant before building and using
package recaptcha

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

type recaptchaResponse struct {
	Success     bool      `json:"success"`
	Score       float64   `json:"score"`
	Action      string    `json:"action"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes"`
}

const recaptchaServerName = "https://www.google.com/recaptcha/api/siteverify"

var (
	// Used to convert short text to actual error text. Original from https://developers.google.com/recaptcha/docs/verify.
	responseErrors = map[string]string{
		"missing-input-secret":   "the secret parameter is missing",
		"invalid-input-secret":   "the secret parameter is invalid or malformed",
		"missing-input-response": "the response parameter is missing",
		"invalid-input-response": "the response parameter is invalid or malformed",
		"bad-request":            "the request is invalid or malformed",
		"timeout-or-duplicate":   "the response is no longer valid - too old or used previously",
	}
	// Your site's private key.
	recaptchaPrivateKey string
)

// check will construct the request to the verification API, send it, and return the result.
func check(remoteip, response string) (recaptchaResponse, error) {
	var r recaptchaResponse
	resp, err := http.PostForm(recaptchaServerName,
		url.Values{"secret": {recaptchaPrivateKey}, "remoteip": {remoteip}, "response": {response}})
	if err != nil {
		return r, fmt.Errorf("post error: %w", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return r, fmt.Errorf("read error: could not read body: %w", err)
	}
	err = json.Unmarshal(body, &r)
	if err != nil {
		return r, fmt.Errorf("read error: JSON unmarshal error: %w", err)
	}
	return r, nil
}

// Confirm is the public interface function that validates a V2 reCAPTCHA token.
// It accepts the client ip address and the token returned to the client after completing the challenge.
// It returns a boolean value indicating whether or not the client token is authentic, meaning the challenge
// was answered correctly.
func Confirm(remoteip, response string) (bool, error) {
	resp, err := check(remoteip, response)
	if err != nil {
		return false, err
	}
	return resp.Success, convertErrorCodes(resp.ErrorCodes)
}

// ConfirmV3 will return the authenticity, score, and action of a V3 captcha.
func ConfirmV3(remoteip, response string) (success bool, score float64, action string, err error){
	resp, err := check(remoteip, response)
	if err != nil {
		return false, 0.0, "", err
	}
	return resp.Success, resp.Score, resp.Action, convertErrorCodes(resp.ErrorCodes)
}

// turn any error codes into actual language describing the problem.
func convertErrorCodes(errorCodes []string) error {
	if len(errorCodes) == 0 {
		return nil
	}
	for i, e := range errorCodes {
		code, ok := responseErrors[e]
		if ok {
			errorCodes[i] = code
		} else {
			errorCodes[i] = fmt.Sprintf("unknown error code %s", e)
		}
	}
	return fmt.Errorf("reCAPTCHA request errors: %v", errorCodes)
}

// Init allows the webserver or code evaluating the reCAPTCHA token input to set the
// reCAPTCHA private key (string) value, which will be different for every domain.
func Init(key string) {
	recaptchaPrivateKey = key
}
