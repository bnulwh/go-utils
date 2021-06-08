package go_utils

import (
	"encoding/json"
	"github.com/bnulwh/logrus"
)

// ToJson object to json string
func ToJson(v interface{}) string {
	dt, err := json.Marshal(v)
	if err != nil {
		logrus.Errorf("to json failed: %v", err)
		return ""
	}
	return string(dt)
}
