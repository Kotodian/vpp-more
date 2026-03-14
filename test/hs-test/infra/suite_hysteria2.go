package hst

import (
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	"go.fd.io/govpp/api"
	"go.fd.io/govpp/binapi/session"
)

var hysteria2Tests = map[string][]func(s *Hysteria2Suite){}

type Hysteria2Suite struct {
	HstSuite
	Interfaces struct {
		Tap *NetInterface
	}
	Containers struct {
		Vpp       *Container
		Hy2Client *Container
		Curl      *Container
	}
	Ports struct {
		ServerPort  string
		SocksPort   string
		BackendPort string
	}
	CkpairIndex uint32
}

func RegisterHysteria2Tests(tests ...func(s *Hysteria2Suite)) {
	hysteria2Tests[GetTestFilename()] = tests
}

func (s *Hysteria2Suite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.LoadNetworkTopology("tap")
	s.LoadContainerTopology("hysteria2")
	s.Interfaces.Tap = s.GetInterfaceByName("htapvpp")
	s.Containers.Vpp = s.GetContainerByName("vpp")
	s.Containers.Hy2Client = s.GetContainerByName("hy2-client")
	s.Containers.Curl = s.GetContainerByName("curl")
	s.Ports.ServerPort = s.GeneratePort()
	s.Ports.SocksPort = s.GeneratePort()
	s.Ports.BackendPort = s.GeneratePort()
}

func (s *Hysteria2Suite) SetupTest() {
	s.HstSuite.SetupTest()

	var sessionConfig Stanza
	sessionConfig.NewStanza("session").Append("enable").Append("use-app-socket-api").Close()
	var memoryConfig Stanza
	memoryConfig.NewStanza("memory").Append("main-heap-size 2G").Close()

	vpp, _ := s.Containers.Vpp.newVppInstance(s.Containers.Vpp.AllocatedCpus, memoryConfig, sessionConfig)

	AssertNil(vpp.Start())
	Log("=== LOADED PLUGINS ===")
	Log(vpp.Vppctl("show plugins"))
	Log("=== END PLUGINS ===")
	AssertNil(vpp.CreateTap(s.Interfaces.Tap, false, 1), "failed to create tap interface")

	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}

	// Load TLS cert/key pair via govpp API
	s.CkpairIndex = s.addCertKeyPair()

	// Start hysteria2 server
	serverAddr := fmt.Sprintf("https://%s:%s", s.VppAddr(), s.Ports.ServerPort)
	Log(vpp.Vppctl("hysteria2 server add uri %s ckpair %d auth-secret testpassword",
		serverAddr, s.CkpairIndex))
}

func (s *Hysteria2Suite) TeardownTest() {
	defer s.HstSuite.TeardownTest()
	vpp := s.Containers.Vpp.VppInstance
	if CurrentSpecReport().Failed() {
		Log(vpp.Vppctl("show hysteria2 server"))
		Log(vpp.Vppctl("show session verbose 2"))
		Log(vpp.Vppctl("show error"))
		Log(vpp.Vppctl("show quic"))
	}
}

func (s *Hysteria2Suite) VppAddr() string {
	return s.Interfaces.Tap.Ip4AddressString()
}

func (s *Hysteria2Suite) HostAddr() string {
	return s.Interfaces.Tap.Host.Ip4AddressString()
}

func (s *Hysteria2Suite) addCertKeyPair() uint32 {
	certBytes, err := os.ReadFile("resources/cert/localhost.crt")
	AssertNil(err, "failed to read cert file")
	keyBytes, err := os.ReadFile("resources/cert/localhost.key")
	AssertNil(err, "failed to read key file")

	certkey := append(certBytes, keyBytes...)
	req := &session.AppAddCertKeyPair{
		CertLen:    uint16(len(certBytes)),
		CertkeyLen: uint16(len(certkey)),
		Certkey:    certkey,
	}

	vpp := s.Containers.Vpp.VppInstance
	if err := vpp.ApiStream.SendMsg(req); err != nil {
		AssertNil(err, "failed to send AppAddCertKeyPair")
	}
	replymsg, err := vpp.ApiStream.RecvMsg()
	AssertNil(err, "failed to recv AppAddCertKeyPair reply")
	reply := replymsg.(*session.AppAddCertKeyPairReply)
	AssertNil(api.RetvalToVPPApiError(reply.Retval), "AppAddCertKeyPair failed")
	Log("added cert-key pair, index=%d", reply.Index)
	return reply.Index
}

func (s *Hysteria2Suite) StartHy2Client(authSecret string, opts ...string) {
	hy2 := s.Containers.Hy2Client
	AssertNil(hy2.Create())

	serverPort := s.Ports.ServerPort
	bandwidth := ""
	if len(opts) > 0 {
		serverPort = opts[0]
	}
	if len(opts) > 1 {
		bandwidth = opts[1]
	}
	settings := struct {
		ServerAddr string
		AuthSecret string
		SocksAddr  string
		Bandwidth  string
	}{
		ServerAddr: s.VppAddr() + ":" + serverPort,
		AuthSecret: authSecret,
		SocksAddr:  "0.0.0.0:" + s.Ports.SocksPort,
		Bandwidth:  bandwidth,
	}
	hy2.CreateConfigFromTemplate(
		"/tmp/hy2/config.yaml",
		"./resources/hysteria2/client.yaml",
		settings,
	)
	AssertNil(hy2.Start())
	hy2.ExecServer(false, "bash -c 'hysteria client -c /tmp/hy2/config.yaml &> /tmp/hy2/client.log'")
}

var _ = Describe("Hysteria2Suite", Ordered, ContinueOnFailure, Label("Hysteria2"), func() {
	var s Hysteria2Suite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SetupTest()
	})
	AfterAll(func() {
		s.TeardownSuite()
	})
	AfterEach(func() {
		s.TeardownTest()
	})

	for filename, tests := range hysteria2Tests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			testName := filename + "/" + strings.Split(funcValue.Name(), ".")[2]
			It(testName, func(ctx SpecContext) {
				Log("[* TEST BEGIN]: " + testName)
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})
