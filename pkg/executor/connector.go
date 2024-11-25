package executor

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Connector provides factory methods to create Remote executor. Each executor is connected to a single SSH hostAddr.
type Connector struct {
	privateKey            string
	timeout               time.Duration
	enableAgent           bool
	enableAgentForwarding bool
	logs                  Logs
}

// In the ProxyCommand variables can be used %h, %p, %r (%r - username)
// before executing the command they needs to be replaced with the actual values
func SubstituteProxyCommand(username, address string, proxyCommand []string) ([]string, error) {
	if len(proxyCommand) == 0 {
		return []string{}, nil
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("failed to split hostAddr and port: %w", err)
	}

	cmdArgs := make([]string, len(proxyCommand))

	for i, arg := range proxyCommand {
		arg = strings.Replace(arg, "%h", host, -1)
		if port != "" {
			arg = strings.Replace(arg, "%p", port, -1)
		}
		arg = strings.Replace(arg, "%r", username, -1)
		cmdArgs[i] = arg
	}
	return cmdArgs, nil
}

// NewConnector creates a new Connector for a given user and private key.
func NewConnector(privateKey string, timeout time.Duration, logs Logs) (res *Connector, err error) {
	res = &Connector{privateKey: privateKey, timeout: timeout, logs: logs}
	if privateKey == "" {
		res.enableAgent = true
		log.Printf("[DEBUG] no private key provided, use ssh agent only")
		return res, nil
	}
	log.Printf("[DEBUG] use private key %q", privateKey)
	if _, err := os.Stat(privateKey); os.IsNotExist(err) {
		return nil, fmt.Errorf("private key file %q does not exist", privateKey)
	}
	return res, nil
}

// WithAgent enables ssh agent for authentication.
func (c *Connector) WithAgent() *Connector {
	log.Printf("[DEBUG] use ssh agent")
	c.enableAgent = true
	return c
}

// WithAgentForwarding enables ssh agent forwarding.
func (c *Connector) WithAgentForwarding() *Connector {
	log.Printf("[DEBUG] use ssh agent forwarding")
	c.enableAgentForwarding = true
	return c
}

// Connect connects to a remote hostAddr and returns a remote executer, caller must close.
func (c *Connector) Connect(ctx context.Context, hostAddr, hostName, user string, proxyCommand []string) (*Remote, error) {
	log.Printf("[DEBUG] connect to %q (%s), user %q, proxy command: %s", hostAddr, hostName, user, proxyCommand)
	client, err := c.sshClient(ctx, hostAddr, user, proxyCommand)
	if err != nil {
		return nil, err
	}
	return &Remote{client: client, hostAddr: hostAddr, hostName: hostName, logs: c.logs.WithHost(hostAddr, hostName)}, nil
}

func (c *Connector) forwardAgent(client *ssh.Client) error {
	if !c.enableAgentForwarding {
		return nil
	}

	aconn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return fmt.Errorf("unable to connect to ssh agent: %w", err)
	}

	aclient := agent.NewClient(aconn)
	if err = agent.ForwardToAgent(client, aclient); err != nil {
		return fmt.Errorf("failed to forward agent: %w", err)
	}

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create new session: %w", err)
	}
	defer session.Close()

	if err := agent.RequestAgentForwarding(session); err != nil {
		return fmt.Errorf("failed to requst agent forwarding: %w", err)
	}

	return nil
}

func sshDialWithProxy(ctx context.Context, host string, cmdArgs []string, config *ssh.ClientConfig) (*ssh.Client, error) {

	client, server := net.Pipe()

	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin = server
	cmd.Stdout = server
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	ncc, chans, reqs, err := ssh.NewClientConn(client, host, config)
	if err != nil {
		return nil, err
	}

	return ssh.NewClient(ncc, chans, reqs), nil

}

func (c *Connector) sshClient(ctx context.Context, host, user string, proxyCommand []string) (session *ssh.Client, err error) {
	var conn net.Conn
	var client *ssh.Client

	log.Printf("[DEBUG] create ssh session to %s, user %s", host, user)
	log.Printf("[DEBUG] ProxyCommand %s ", proxyCommand)
	if !strings.Contains(host, ":") {
		host += ":22"
	}

	cmdArgs, err := SubstituteProxyCommand(user, host, proxyCommand)
	if err != nil {
		return nil, fmt.Errorf("failed to parse proxy command: %w", err)
	}

	conf, err := c.sshConfig(user, c.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create ssh config: %w", err)
	}

	if len(proxyCommand) == 0 {
		dialer := net.Dialer{Timeout: c.timeout}
		conn, err = dialer.DialContext(ctx, "tcp", host)
		if err != nil {
			return nil, fmt.Errorf("failed to dial: %w", err)
		}

		ncc, chans, reqs, err := ssh.NewClientConn(conn, host, conf)
		if err != nil {
			return nil, fmt.Errorf("failed to create client connection to %s: %v", host, err)
		}
		client = ssh.NewClient(ncc, chans, reqs)

	} else {
		client, err = sshDialWithProxy(ctx, host, cmdArgs, conf)
		if err != nil {
			return nil, fmt.Errorf("failed to create client connection wtth proxy command %s, to %s: %v", proxyCommand, host, err)
		}
	}

	if err := c.forwardAgent(client); err != nil {
		return nil, fmt.Errorf("failed to forward agent to %s: %v", host, err)
	}

	log.Printf("[DEBUG] ssh session created to %s", host)
	return client, nil
}

func (c *Connector) sshConfig(user, privateKeyPath string) (*ssh.ClientConfig, error) {

	// getAuth returns a list of ssh.AuthMethod to be used for authentication.
	// if ssh agent is enabled, it will be used, otherwise private key will be used.
	getAuth := func() (auth []ssh.AuthMethod, err error) {
		if privateKeyPath == "" || c.enableAgent {
			if aconn, e := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); e == nil {
				auth = append(auth, ssh.PublicKeysCallback(agent.NewClient(aconn).Signers))
				log.Printf("[DEBUG] ssh agent found at %s", os.Getenv("SSH_AUTH_SOCK"))
			} else {
				return nil, fmt.Errorf("unable to connect to ssh agent: %w", e)
			}
			return auth, nil
		}

		key, err := os.ReadFile(privateKeyPath) // nolint
		if err != nil {
			return nil, fmt.Errorf("unable to read private key: %vw", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("unable to parse private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
		return auth, nil
	}

	auth, err := getAuth()
	if err != nil {
		return nil, fmt.Errorf("failed to get ssh auth: %w", err)
	}

	sshConfig := &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // nolint
	}

	return sshConfig, nil
}

func (c *Connector) String() string {
	return fmt.Sprintf("ssh connector with private key %s.., timeout %v, agent %v", c.privateKey[:8], c.timeout, c.enableAgent)
}
