package ncloud

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Access struct {
	AccessKey string
	SecretKey string
}

// Request 함수에 추가 헤더를 지원하도록 변경
func Request(access *Access, method string, endpoint string, url string, body interface{}, extraHeaders map[string]string) (*http.Response, error) {
	req, err := MakeRequest(access, method, endpoint, url, body, extraHeaders)
	if err != nil {
		return nil, fmt.Errorf("fail to Create HTTP Request: %v", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fail to HTTP Request: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("fail(CODE=%d): %s %v %s", resp.StatusCode, url, req.Header, string(bodyBytes))
	}

	return resp, nil
}

// MakeRequest: 추가 헤더를 받을 수 있도록 개선
func MakeRequest(access *Access, method string, endpoint string, url string, body interface{}, extraHeaders map[string]string) (*http.Request, error) {
	var bodyReader io.Reader

	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %v", err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(method, endpoint+url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("fail to Create HTTP Request: %v", err)
	}

	timestamp := time.Now().UnixMilli()
	signature := MakeSignature(access.AccessKey, access.SecretKey, method, url, timestamp)

	// 기본 헤더 추가
	req.Header.Set("x-ncp-apigw-timestamp", fmt.Sprintf("%d", timestamp))
	req.Header.Set("x-ncp-iam-access-key", access.AccessKey)
	req.Header.Set("x-ncp-apigw-signature-v2", signature)
	req.Header.Set("Accept", "application/json")

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// 추가 헤더 적용
	for key, value := range extraHeaders {
		req.Header.Set(key, value)
	}

	return req, nil
}

func MakeSignature(accessKeyID string, secretKey string, method string, path string, epochTime int64) string {
	const space = " "
	const newLine = "\n"
	h := hmac.New(sha256.New, []byte(secretKey))
	h.Write([]byte(method))
	h.Write([]byte(space))
	h.Write([]byte(path))
	h.Write([]byte(newLine))
	h.Write([]byte(fmt.Sprintf("%d", epochTime)))
	h.Write([]byte(newLine))
	h.Write([]byte(accessKeyID))
	rawSignature := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(rawSignature)
}
