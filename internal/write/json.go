package write

import (
	"encoding/json"
	"net/http"

	"github.com/sirupsen/logrus"
)

// JSON response
func JSON(statusCode int, w http.ResponseWriter, data interface{}) {
	resp, err := json.Marshal(data)
	if err != nil {
		logrus.Error(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if _, err = w.Write(resp); err != nil {
		logrus.Error(err)
		return
	}
}
