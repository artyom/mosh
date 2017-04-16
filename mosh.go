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
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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
	hostKeyCallback, err := knownHostsKeyMatch(os.ExpandEnv("$HOME/.ssh/known_hosts"))
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
		User:            login,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signers...)},
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
	if err := session.RequestPty(os.Getenv("TERM"), 80, 25, make(ssh.TerminalModes)); err != nil {
		return 0, "", err
	}
	rdata, err := session.CombinedOutput("mosh-server new -p " + moshPorts)
	if err != nil {
		os.Stderr.Write(rdata)
		return 0, "", err
	}
	var moshPort int
	var moshKey string
	_, err = fmt.Fscanf(bytes.NewReader(rdata), "\nMOSH CONNECT %d %s\n", &moshPort, &moshKey)
	return moshPort, moshKey, err
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
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: mosh [flags] hostname")
		flag.PrintDefaults()
	}
}

func knownHostsKeyMatch(name string) (ssh.HostKeyCallback, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	var lineNo int
	for scanner.Scan() {
		lineNo++
		if bytes.HasPrefix(scanner.Bytes(), []byte("#")) {
			continue
		}
		_, _, key, _, _, err := ssh.ParseKnownHosts(scanner.Bytes())
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", lineNo, err)
		}
		m[ssh.FingerprintSHA256(key)] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		if _, ok := m[fp]; ok {
			return nil
		}
		return fmt.Errorf("key %q for %q not found in known_hosts", fp, hostname)
	}, nil
}
