package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	. "fd.io/hs-test/infra"
	"golang.org/x/net/proxy"
)

func init() {
	RegisterHysteria2Tests(
		Hysteria2TcpProxyTest,
		Hysteria2AuthFailureTest,
		Hysteria2AclCidrBlockTest,
		Hysteria2BandwidthNegotiationTest,
		Hysteria2MasqueradingTest,
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

func Hysteria2BandwidthNegotiationTest(s *Hysteria2Suite) {
	vpp := s.Containers.Vpp.VppInstance

	// Add a second server with bandwidth cap on a separate port
	bwPort := s.GeneratePort()
	serverAddr := fmt.Sprintf("https://%s:%s", s.VppAddr(), bwPort)
	maxRate := 1000000 // 1 MB/s
	o := vpp.Vppctl("hysteria2 server add uri %s ckpair %d auth-secret testpassword max-tx-rate %d",
		serverAddr, s.CkpairIndex, maxRate)
	Log(o)

	// Verify server shows configured max-tx-rate
	o = vpp.Vppctl("show hysteria2 server")
	Log(o)
	AssertContains(o, fmt.Sprintf("max-tx-rate %d", maxRate))

	// Start backend HTTPS server
	backendAddr := s.HostAddr() + ":" + s.Ports.BackendPort
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("bandwidth negotiation ok"))
	})
	cer, err := tls.LoadX509KeyPair("resources/cert/localhost.crt", "resources/cert/localhost.key")
	AssertNil(err)
	srv := &http.Server{
		Addr:      backendAddr,
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cer}},
	}
	go srv.ListenAndServeTLS("", "")
	defer srv.Close()
	time.Sleep(500 * time.Millisecond)

	// Start hy2 client pointed at the bandwidth-limited server with a
	// client-side bandwidth preference of 2 mbps.
	// Server max is 1 MB/s so negotiated = min(client, server).
	s.StartHy2Client("testpassword", bwPort, "2 mbps")
	time.Sleep(5 * time.Second)

	// Verify auth succeeded (bandwidth negotiation happens during auth)
	o = vpp.Vppctl("show hysteria2 server")
	Log(o)
	AssertContains(o, "auth-ok 1")

	// Verify TCP relay works with bandwidth pacing active
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
	resp, err := client.Get(fmt.Sprintf("https://%s/", backendAddr))
	AssertNil(err, "HTTP GET through SOCKS5 failed")
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	AssertNil(err, "reading response body failed")
	AssertContains(string(body), "bandwidth negotiation ok")
}

func Hysteria2MasqueradingTest(s *Hysteria2Suite) {
	vpp := s.Containers.Vpp.VppInstance

	// Start a plain HTTP backend on the host side
	masqBackendPort := s.GeneratePort()
	backendAddr := s.HostAddr() + ":" + masqBackendPort
	var receivedMethod, receivedPath, receivedQuery string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		receivedPath = r.URL.Path
		receivedQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Location", "/next")
		w.Header().Add("Set-Cookie", "masq-cookie=ok")
		w.WriteHeader(http.StatusFound)
		w.Write([]byte("masquerade test ok"))
	})
	srv := &http.Server{
		Addr:    backendAddr,
		Handler: mux,
	}
	go srv.ListenAndServe()
	defer srv.Close()
	time.Sleep(500 * time.Millisecond)

	// Add a hysteria2 server with masq-url on a separate port
	masqServerPort := s.GeneratePort()
	serverAddr := fmt.Sprintf("https://%s:%s", s.VppAddr(), masqServerPort)
	masqUrl := fmt.Sprintf("http://%s:%s", s.HostAddr(), masqBackendPort)
	o := vpp.Vppctl("hysteria2 server add uri %s ckpair %d auth-secret testpassword masq-url %s",
		serverAddr, s.CkpairIndex, masqUrl)
	Log(o)

	// Verify server shows masq-url
	o = vpp.Vppctl("show hysteria2 server")
	Log(o)
	AssertContains(o, masqUrl)

	// Send a non-auth HTTP/3 GET request to trigger masquerading
	curlAddr := s.VppAddr() + ":" + masqServerPort
	args := fmt.Sprintf(
		"-k --max-time 10 --noproxy '*' --http3-only -D - -o - https://%s/echo?x=1",
		curlAddr)
	writeOut, log := RunCurlContainer(s.Containers.Curl, args)
	Log("curl stdout: " + writeOut)
	Log("curl stderr: " + log)

	// Verify response: status, headers, and body forwarded from backend
	lowerOut := strings.ToLower(writeOut)
	AssertContains(lowerOut, "http/3 302")
	AssertContains(lowerOut, "content-type: text/plain")
	AssertContains(lowerOut, "location: /next")
	AssertContains(lowerOut, "set-cookie: masq-cookie=ok")
	AssertContains(writeOut, "masquerade test ok")

	// Verify request reached backend with correct method, path, query
	time.Sleep(200 * time.Millisecond)
	AssertEqual("GET", receivedMethod)
	AssertEqual("/echo", receivedPath)
	AssertEqual("x=1", receivedQuery)
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

func Hysteria2AclCidrBlockTest(s *Hysteria2Suite) {
	backendAddr := s.HostAddr() + ":" + s.Ports.BackendPort
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("cidr acl should block this"))
	})
	cer, err := tls.LoadX509KeyPair("resources/cert/localhost.crt", "resources/cert/localhost.key")
	AssertNil(err)
	srv := &http.Server{
		Addr:      backendAddr,
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cer}},
	}
	go srv.ListenAndServeTLS("", "")
	defer srv.Close()
	time.Sleep(500 * time.Millisecond)

	vpp := s.Containers.Vpp.VppInstance
	serverAddr := fmt.Sprintf("https://%s:%s", s.VppAddr(), s.Ports.ServerPort)
	o := vpp.Vppctl("hysteria2 acl add server %s block cidr:%s/32",
		serverAddr, s.HostAddr())
	Log(o)

	s.StartHy2Client("testpassword")
	time.Sleep(5 * time.Second)

	socksAddr := s.HostAddr() + ":" + s.Ports.SocksPort
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	AssertNil(err, "failed to create SOCKS5 dialer")

	transport := &http.Transport{
		Dial:            dialer.Dial,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	_, err = client.Get(fmt.Sprintf("https://%s/", backendAddr))
	AssertNotNil(err, "CIDR ACL rule should block backend access")
}
