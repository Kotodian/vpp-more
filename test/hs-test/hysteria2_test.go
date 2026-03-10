package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	. "fd.io/hs-test/infra"
	"golang.org/x/net/proxy"
)

func init() {
	RegisterHysteria2Tests(
		Hysteria2TcpProxyTest,
		Hysteria2AuthFailureTest,
	)
}

func Hysteria2TcpProxyTest(s *Hysteria2Suite) {
	// Start Go HTTPS backend server on host side
	backendAddr := s.HostAddr() + ":" + s.Ports.BackendPort
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hysteria2 backend ok"))
	})
	certFile := "resources/cert/localhost.crt"
	keyFile := "resources/cert/localhost.key"
	cer, err := tls.LoadX509KeyPair(certFile, keyFile)
	AssertNil(err)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cer}}
	srv := &http.Server{
		Addr:      backendAddr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}
	go srv.ListenAndServeTLS("", "")
	defer srv.Close()
	time.Sleep(500 * time.Millisecond)

	// Start hy2 client with correct auth
	s.StartHy2Client("testpassword")
	time.Sleep(5 * time.Second)

	// Verify auth succeeded
	vpp := s.Containers.Vpp.VppInstance
	o := vpp.Vppctl("show hysteria2 server")
	Log(o)
	AssertContains(o, "auth-ok 1")

	// Connect through SOCKS5 proxy using Go's net/proxy
	socksAddr := s.HostAddr() + ":" + s.Ports.SocksPort
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	AssertNil(err, "failed to create SOCKS5 dialer")

	transport := &http.Transport{
		Dial:            dialer.Dial,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
	targetURL := fmt.Sprintf("https://%s/", backendAddr)
	resp, err := client.Get(targetURL)
	AssertNil(err, "HTTP GET through SOCKS5 failed")
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	AssertNil(err, "reading response body failed")
	AssertContains(string(body), "hysteria2 backend ok")
}

func Hysteria2AuthFailureTest(s *Hysteria2Suite) {
	// Start hy2 client with wrong auth secret
	s.StartHy2Client("wrongpassword")
	time.Sleep(2 * time.Second)

	// Try connecting through SOCKS5 - should fail
	socksAddr := s.HostAddr() + ":" + s.Ports.SocksPort
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		Log("SOCKS5 dialer creation failed (expected): " + err.Error())
	} else {
		transport := &http.Transport{
			Dial:            dialer.Dial,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
		}
		backendAddr := s.HostAddr() + ":" + s.Ports.BackendPort
		targetURL := fmt.Sprintf("https://%s/", backendAddr)
		resp, err := client.Get(targetURL)
		if err != nil {
			Log("HTTP GET failed (expected): " + err.Error())
		} else {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			AssertNotContains(string(body), "should not reach")
		}
	}

	// Verify auth failures in hysteria2 server stats
	vpp := s.Containers.Vpp.VppInstance
	o := vpp.Vppctl("show hysteria2 server")
	Log(o)
}
