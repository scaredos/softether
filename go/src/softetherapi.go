// Copyright 2021 scaredos

// Package softetherapi implements a client library for SoftEther in Go

package softetherapi

import (
	"fmt"
	"net/http"
)

type Client struct {
	ip         string
	port       int
	hubname    string
	password   string
	baseURL    string
	httpClient *http.Client
}

func NewClient(ip string, port int, hubname, password, baseURL string) Client {
	return Client{ip: ip, port: port, hubname: hubname, password: password, baseURL: fmt.Sprintf("https://%s:%d/api", ip, port)}
}
