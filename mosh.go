// Command mosh is an alternative wrapper to mosh-client command that plays well with socks proxies.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/net/proxy"

	"github.com/artyom/autoflags"
)

func main() {
	defaultUser := os.Getenv("MOSH_USER")
	if defaultUser == "" {
		defaultUser = os.Getenv("USER")
	}
	defaultPorts := os.Getenv("MOSH_PORTS")
	if defaultPorts == "" {
		defaultPorts = "60000:60050"
	}
	params := struct {
		SSHPort   int           `flag:"sshport,ssh port to use"`
		Login     string        `flag:"l,login"`
		MoshPorts string        `flag:"p,server-side UDP port or colon-separated range"`
		Timeout   time.Duration `flag:"timeout,ssh connect timeout"`
	}{
		SSHPort:   22,
		Login:     defaultUser,
		MoshPorts: defaultPorts,
		Timeout:   5 * time.Second,
	}
	autoflags.Define(&params)
	flag.Parse()
	if len(flag.Args()) != 1 {
		flag.Usage()
		os.Exit(1)
	}
	addr := flag.Args()[0]
	ips, err := net.LookupIP(addr)
	if err != nil {
		log.Fatal(err)
	}
	if len(ips) == 0 {
		log.Fatalf("name %q resolved to %v", addr, ips)
	}
	clientPath, err := exec.LookPath("mosh-client")
	if err != nil {
		log.Fatal(err)
	}

	port, key, err := runServer(addr, params.Login, params.MoshPorts, params.SSHPort, params.Timeout)
	if err != nil {
		log.Fatal(err)
	}
	newEnv := append([]string{}, os.Environ()...)
	newEnv = append(newEnv, "MOSH_KEY="+key)
	log.Fatal(syscall.Exec(clientPath, []string{"mosh-client", ips[0].String(), strconv.Itoa(port)}, newEnv))
}

func runServer(addr, login, moshPorts string, port int, tout time.Duration) (int, string, error) {
	hostKeyCallback, err := knownhosts.New(os.ExpandEnv("$HOME/.ssh/known_hosts"))
	if err != nil {
		return 0, "", err
	}
	var sshAgent agent.Agent
	agentConn, err := net.DialTimeout("unix", os.Getenv("SSH_AUTH_SOCK"), tout)
	if err != nil {
		return 0, "", err
	}
	sshAgent = agent.NewClient(agentConn)
	defer agentConn.Close()

	signers, err := sshAgent.Signers()
	if err != nil {
		return 0, "", err
	}
	sshConfig := &ssh.ClientConfig{
		User: login,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signers...),
			ssh.KeyboardInteractive(keyboardChallenge)},
		HostKeyCallback: hostKeyCallback,
	}
	client, err := sshDial("tcp", net.JoinHostPort(addr, strconv.Itoa(port)), sshConfig)
	if err != nil {
		return 0, "", err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return 0, "", err
	}
	defer session.Close()
	width, height := 80, 25
	if w, h, err := terminal.GetSize(0); err == nil {
		width, height = w, h
	}
	if err := session.RequestPty(os.Getenv("TERM"), height, width, make(ssh.TerminalModes)); err != nil {
		return 0, "", err
	}
	rdata, err := session.CombinedOutput("mosh-server new -p " + moshPorts)
	if err != nil {
		os.Stderr.Write(rdata)
		return 0, "", err
	}
	return parsePortKey(rdata)
}

func parsePortKey(b []byte) (port int, key string, err error) {
	for s := bufio.NewScanner(bytes.NewReader(b)); s.Scan(); {
		if !bytes.HasPrefix(s.Bytes(), []byte("MOSH CONNECT")) {
			continue
		}
		fields := strings.Fields(s.Text())
		if len(fields) != 4 {
			return 0, "", fmt.Errorf("unexpected response line from mosh-server: %q", s.Text())
		}
		port, err = strconv.Atoi(fields[2])
		if err != nil {
			return 0, "", err
		}
		key = fields[3]
		return port, key, nil
	}
	return 0, "", fmt.Errorf("no 'MOSH CONNECT' line from mosh-server")
}

func sshDial(network, addr string, config *ssh.ClientConfig) (*ssh.Client, error) {
	proxyDialer := proxy.FromEnvironment()
	conn, err := proxyDialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

func init() {
	log.SetFlags(0)
	log.SetPrefix("mosh: ")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: mosh [flags] hostname")
		flag.PrintDefaults()
	}
}

func keyboardChallenge(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
	if len(questions) != 0 {
		return nil, fmt.Errorf("keyboard interactive challenge is not supported")
	}
	// https://godoc.org/golang.org/x/crypto/ssh#KeyboardInteractiveChallenge
	//
	// After successful authentication, the server may send
	// a challenge with no questions, for which the user and
	// instruction messages should be printed.
	if user != "" {
		log.Println(user)
	}
	if instruction != "" {
		log.Println(instruction)
	}
	return nil, nil
}
