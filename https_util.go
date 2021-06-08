package go_utils

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/bnulwh/logrus"
	"io/ioutil"
	"net/http"
)

const (
	ApplicationJson   = "application/json"
	SuccessStatusCode = 200
)

// PostHttpsJsonDirectRequest post https json body direct and return bytes
func PostHttpsJsonDirectRequest(url string, body []byte) ([]byte, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport}
	response, err := client.Post(url, ApplicationJson, bytes.NewReader(body))
	if err != nil {
		logrus.Errorf("post %v failed: %v", url, err)
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != SuccessStatusCode {
		logrus.Errorf("response from %v return %v", url, response.StatusCode)
		return nil, fmt.Errorf("response from %v return %v", url, response.StatusCode)
	}
	bs, err := ioutil.ReadAll(response.Body)
	if err != nil {
		logrus.Errorf("read body failed: %v", err)
		return nil, err
	}
	return bs, nil
}

// PostHttpsJsonRequest post https json request and return map
func PostHttpsJsonRequest(url string, params map[string]interface{}) (map[string]interface{}, error) {
	body, err := json.Marshal(params)
	if err != nil {
		logrus.Errorf("marshal to json failed: %v", err)
		return nil, err
	}
	resp, err := PostHttpsJsonDirectRequest(url, body)
	if err != nil {
		return nil, err
	}
	mp := make(map[string]interface{})
	err = json.Unmarshal(resp, &mp)
	if err != nil {
		logrus.Errorf("unmarshal body failed: %v", err)
		return nil, err
	}
	return mp, nil
}
