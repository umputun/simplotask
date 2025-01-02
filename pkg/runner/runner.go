package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/go-pkgz/stringutils"
	"github.com/go-pkgz/syncs"

	"github.com/umputun/spot/pkg/config"
	"github.com/umputun/spot/pkg/config/deepcopy"
	"github.com/umputun/spot/pkg/executor"
)

//go:generate moq -out mocks/connector.go -pkg mocks -skip-ensure -fmt goimports . Connector
//go:generate moq -out mocks/playbook.go -pkg mocks -skip-ensure -fmt goimports . Playbook

// Process is a struct that holds the information needed to run a process.
// It responsible for running a task on a target hosts.
type Process struct {
	Concurrency int
	Connector   Connector
	Playbook    Playbook
	Logs        executor.Logs
	Verbose     bool
	Verbose2    bool
	Dry         bool
	SSHShell    string

	Skip []string
	Only []string
}

// Connector is an interface for connecting to a host, and returning remote executer.
type Connector interface {
	Connect(ctx context.Context, hostAddr, hostName, user string) (*executor.Remote, error)
}

// Playbook is an interface for getting task and target information from playbook.
type Playbook interface {
	AllTasks() []config.Task
	Task(name string) (*config.Task, error)
	TargetHosts(name string) ([]config.Destination, error)
	AllSecretValues() []string
	UpdateTasksTargets(vars map[string]string)
	UpdateRegisteredVars(vars map[string]string)
}

// ProcResp holds the information about processed commands and hosts.
type ProcResp struct {
	Vars       map[string]string
	Registered map[string]string
	Commands   int
	Hosts      int
}

// taskOnHostResp is the response from runTaskOnHost.
type taskOnHostResp struct {
	count      int
	vars       map[string]string
	registered map[string]string
}

// Run runs a task for a set of target hosts. Runs in parallel with limited concurrency,
// each host is processed in separate goroutine. Returns ProcResp with the information about processed commands and hosts
// plus vars from all thr commands.
func (p *Process) Run(ctx context.Context, task, target string) (s ProcResp, err error) {
	tsk, err := p.Playbook.Task(task)
	if err != nil {
		return ProcResp{}, fmt.Errorf("can't get task %s: %w", task, err)
	}
	log.Printf("[DEBUG] task %q has %d commands", task, len(tsk.Commands))

	allVars := make(map[string]string)
	allRegistered := make(map[string]string)
	targetHosts, err := p.Playbook.TargetHosts(target)
	if err != nil {
		return ProcResp{}, fmt.Errorf("can't get target %s: %w", target, err)
	}
	log.Printf("[DEBUG] target hosts (%d) %+v", len(targetHosts), targetHosts)

	var commands int32
	lock := sync.Mutex{}

	wg := syncs.NewErrSizedGroup(p.Concurrency, syncs.Context(ctx), syncs.Preemptive)
	for i, host := range targetHosts {
		i, host := i, host //nolint:copyloopvar // copy loop variables in case we downgrade to pre 1.22 go version
		wg.Go(func() error {
			user := host.User // default user from target
			if tsk.User != "" {
				user = tsk.User // override user from task if any set
			}
			resp, e := p.runTaskOnHost(ctx, tsk, fmt.Sprintf("%s:%d", host.Host, host.Port), host.Name, user)
			if i == 0 {
				atomic.AddInt32(&commands, int32(resp.count))
			}

			lock.Lock()
			if e != nil {
				errLog := p.Logs.WithHost(host.Host, host.Name).Err
				errLog.Write([]byte(e.Error())) // nolint
			}
			for k, v := range resp.vars {
				allVars[k] = v
			}
			for k, v := range resp.registered {
				allRegistered[k] = v
			}
			lock.Unlock()

			return e
		})
	}
	err = wg.Wait()

	// execute on-error command if any error occurred during task execution and on-error command is defined
	if err != nil && tsk.OnError != "" {
		p.onError(ctx, err)
	}

	return ProcResp{
		Hosts:      len(targetHosts),
		Commands:   int(atomic.LoadInt32(&commands)),
		Vars:       allVars,
		Registered: allRegistered,
	}, err
}

// Gen generates the list target hosts for a given target, applying templates.
func (p *Process) Gen(targets []string, tmplRdr io.Reader, respWr io.Writer) error {
	targetHosts := []config.Destination{}
	for _, target := range targets {
		hosts, err := p.Playbook.TargetHosts(target)
		if err != nil {
			return fmt.Errorf("can't get target %s: %w", target, err)
		}
		targetHosts = append(targetHosts, hosts...)
	}
	log.Printf("[DEBUG] target hosts (%d) %+v", len(targetHosts), targetHosts)

	// if no reader provided, just encode target hosts as json
	if tmplRdr == nil {
		return json.NewEncoder(respWr).Encode(targetHosts)
	}

	templateBytes, err := io.ReadAll(tmplRdr)
	if err != nil {
		return fmt.Errorf("can't read template: %w", err)
	}

	tmpl, err := template.New("spot").Parse(string(templateBytes))
	if err != nil {
		return fmt.Errorf("can't parse template: %w", err)
	}
	if err = tmpl.Execute(respWr, targetHosts); err != nil {
		return fmt.Errorf("can't execute template: %w", err)
	}

	return nil
}

// runTaskOnHost executes all commands of a task on a target host. hostAddr can be a remote host or localhost with port.
// returns number of executed commands, vars from all commands and error if any.
func (p *Process) runTaskOnHost(ctx context.Context, tsk *config.Task, hostAddr, hostName, user string) (taskOnHostResp, error) {
	report := func(hostAddr, hostName, f string, vals ...any) {
		p.Logs.WithHost(hostAddr, hostName).Info.Printf(f, vals...)
	}
	since := func(st time.Time) time.Duration { return time.Since(st).Truncate(time.Millisecond) }

	stTask := time.Now()

	var remote executor.Interface
	if p.anyRemoteCommand(tsk) && !isLocalHost(hostAddr) {
		// make remote executor only if there is a remote command in the taks
		var err error
		remote, err = p.Connector.Connect(ctx, hostAddr, hostName, user)
		if err != nil {
			if hostName != "" {
				return taskOnHostResp{}, fmt.Errorf("can't connect to %s, user: %s: %w", hostName, user, err)
			}
			return taskOnHostResp{}, err
		}
		defer remote.Close()
		report(hostAddr, hostName, "run task %q, commands: %d\n", tsk.Name, len(tsk.Commands))
	} else {
		report("localhost", "", "run task %q, commands: %d (local)\n", tsk.Name, len(tsk.Commands))
	}

	resp := taskOnHostResp{vars: make(map[string]string), registered: make(map[string]string)}

	// copy task to prevent one task on hostA modifying task on hostB as it does updateVars
	activeTask := deepcopy.Copy(*tsk).(config.Task)
	// set the active user to the task itself. this is done to match the passed user for any upstream handlers,
	// for example, SPOT_REMOTE_USER env var is using task.User and expected to be set to the one used to connect to the host
	activeTask.User = user

	onExitCmds := []execCmd{}
	defer func() {
		// run on-exit commands if any. it is executed after all commands of the task are done or on error
		if len(onExitCmds) > 0 {
			log.Printf("[INFO] run %d on-exit commands for %q on %s", len(onExitCmds), tsk.Name, hostAddr)
			for _, ec := range onExitCmds {
				if _, err := ec.Script(ctx); err != nil {
					report(ec.hostAddr, ec.hostName, "failed on-exit command %q (%v)", ec.cmd.Name, err)
				}
			}
		}
	}()

	for _, cmd := range activeTask.Commands {
		if !p.shouldRunCmd(cmd, hostName, hostAddr) {
			continue
		}

		log.Printf("[INFO] %s", p.infoMessage(cmd, hostAddr, hostName))
		stCmd := time.Now()

		ec := execCmd{
			cmd: cmd, hostAddr: hostAddr, hostName: hostName, tsk: &activeTask, exec: remote,
			verbose: p.Verbose, verbose2: p.Verbose2, sshShell: p.SSHShell, onExit: cmd.OnExit,
		}
		ec = p.pickCmdExecutor(cmd, ec, hostAddr, hostName) // pick executor on dry run or local command

		repHostAddr, repHostName := ec.hostAddr, ec.hostName
		if cmd.Options.Local {
			repHostAddr = "localhost"
			repHostName = ""
		}

		if ec.verbose {
			report(repHostAddr, repHostName, "run command %q", cmd.Name)
		}

		exResp, err := p.execCommand(ctx, ec)
		if exResp.onExit.cmd.Name != "" { // we have on-exit command, save it for later execution
			// this is intentionally before error check, we want to run on-exit command even if the main command failed
			onExitCmds = append(onExitCmds, exResp.onExit)
		}
		if err != nil {
			if !cmd.Options.IgnoreErrors {
				return resp, fmt.Errorf("failed command %q on host %s (%s): %w", cmd.Name, ec.hostAddr, ec.hostName, err)
			}
			report(ec.hostAddr, ec.hostName, "failed command %q%s (%v)", cmd.Name, exResp.details, since(stCmd))
			continue
		}

		p.updateVars(exResp.vars, cmd, &activeTask) // set variables from command output to all commands env in task
		for k, v := range exResp.registered {       // store registered variables from command output
			resp.registered[k] = v
		}
		if exResp.verbose != "" && ec.verbose2 {
			report(repHostAddr, repHostName, exResp.verbose)
		}

		// we don't want to print multiline script name in logs
		// from: completed command "test" {script: /bin/sh -c /tmp/.spot-7113416067113199616/spot-script2358478823} (17ms)
		// we make: completed command "test" {script: /bin/sh -c [multiline script]} (17ms)
		pattern := `(\{script: .+ -c ).+/spot-script.+}`
		re := regexp.MustCompile(pattern)
		details := re.ReplaceAllString(exResp.details, "${1}[multiline script]}")
		report(repHostAddr, repHostName, "completed command %q%s (%v)", cmd.Name, details, since(stCmd))

		resp.count++
		for k, v := range exResp.vars {
			resp.vars[k] = v
		}
	}

	if p.anyRemoteCommand(&activeTask) && !isLocalHost(hostAddr) {
		report(hostAddr, hostName, "completed task %q, commands: %d (%v)\n", activeTask.Name, resp.count, since(stTask))
	} else {
		report("localhost", "", "completed task %q, commands: %d (%v)\n",
			activeTask.Name, resp.count, since(stTask))
	}

	return resp, nil
}

// execCommand executes a single command on a target host.
// It detects the command type based on the fields what are set.
// Even if multiple fields for multiple commands are set, only one will be executed.
func (p *Process) execCommand(ctx context.Context, ec execCmd) (resp execCmdResp, err error) {
	if ec.cmd.OnExit != "" {
		// register on-exit command if any set
		defer func() {
			// we need to defer it because it changes the command name and script
			log.Printf("[DEBUG] defer execution on_exit script on %s for %s", ec.hostAddr, ec.cmd.Name)
			// use the same executor as for the main command but with different script and name
			ec.cmd.Name = "on exit for " + ec.cmd.Name
			ec.cmd.Script = ec.cmd.OnExit
			ec.cmd.OnExit = "" // prevent recursion
			resp.onExit = ec
		}()
	}

	switch {
	case ec.cmd.Script != "":
		log.Printf("[DEBUG] execute script %q on %s", ec.cmd.Name, ec.hostAddr)
		return ec.Script(ctx)
	case ec.cmd.Copy.Source != "" && ec.cmd.Copy.Dest != "":
		log.Printf("[DEBUG] copy file to %s", ec.hostAddr)
		return ec.Copy(ctx)
	case len(ec.cmd.MCopy) > 0:
		log.Printf("[DEBUG] copy multiple files to %s", ec.hostAddr)
		return ec.Mcopy(ctx)
	case ec.cmd.Sync.Source != "" && ec.cmd.Sync.Dest != "":
		log.Printf("[DEBUG] sync files to %s", ec.hostAddr)
		return ec.Sync(ctx)
	case len(ec.cmd.MSync) > 0:
		log.Printf("[DEBUG] sync multiple locations to %s", ec.hostAddr)
		return ec.Msync(ctx)
	case ec.cmd.Delete.Location != "":
		log.Printf("[DEBUG] delete files on %s", ec.hostAddr)
		return ec.Delete(ctx)
	case len(ec.cmd.MDelete) > 0:
		log.Printf("[DEBUG] delete multiple files on %s", ec.hostAddr)
		return ec.MDelete(ctx)
	case ec.cmd.Wait.Command != "":
		log.Printf("[DEBUG] wait for command on %s", ec.hostAddr)
		return ec.Wait(ctx)
	case ec.cmd.Echo != "":
		log.Printf("[DEBUG] echo on %s", ec.hostAddr)
		return ec.Echo(ctx)
	default:
		return execCmdResp{}, fmt.Errorf("unknown command %q", ec.cmd.Name)
	}
}

// pickCmdExecutor returns executor for dry run or local command, otherwise returns the default executor.
func (p *Process) pickCmdExecutor(cmd config.Cmd, ec execCmd, hostAddr, hostName string) execCmd {
	if p.Dry {
		log.Printf("[DEBUG] run dry command %q", cmd.Name)
		if cmd.Options.Local {
			ec.exec = executor.NewDry(p.Logs.WithHost("localhost", ""))
		} else {
			ec.exec = executor.NewDry(p.Logs.WithHost(hostAddr, hostName))
		}
		return ec
	}
	if cmd.Options.Local || isLocalHost(hostAddr) {
		log.Printf("[DEBUG] run local command %q", cmd.Name)
		ec.exec = executor.NewLocal(p.Logs.WithHost("localhost", ""))
		return ec
	}
	return ec
}

// onError executes on-error command locally if any error occurred during task execution and on-error command is defined
func (p *Process) onError(ctx context.Context, err error) {
	// unwrapError unwraps error to get execCmdErr with all details about command execution
	unwrapError := func(err error) (execCmdErr, bool) {
		execErr := &execCmdErr{}
		if errors.As(err, &execErr) {
			return *execErr, true
		}
		multiErr := &syncs.MultiError{}
		if errors.As(err, &multiErr) {
			for _, e := range multiErr.Errors() {
				if errors.As(e, &execErr) {
					// we need only the first error as we don't need to execute
					// on-error command multiple times if multiple commands failed
					return *execErr, true
				}
			}
		}
		return execCmdErr{}, false
	}

	execErr, ok := unwrapError(err)
	if !ok {
		log.Printf("[WARN] can't unwrap error: %v", err)
		return
	}

	ec := execCmd{
		tsk: execErr.exec.tsk,
		cmd: config.Cmd{
			Name:   execErr.exec.tsk.Name,
			Script: execErr.exec.tsk.OnError,
			Options: config.CmdOptions{Local: true, // force local execution for on-error command
				Secrets: execErr.exec.cmd.Options.Secrets},
			SSHShell:    "/bin/sh", // local run always with /bin/sh
			Environment: execErr.exec.cmd.Environment,
			Secrets:     execErr.exec.cmd.Secrets,
		},
		hostAddr: execErr.exec.hostAddr,
		hostName: execErr.exec.hostName,
		verbose:  p.Verbose,
	}

	ec = p.pickCmdExecutor(ec.cmd, ec, "localhost", ec.hostName) // pick executor for local command
	tmpl := templater{
		hostAddr: ec.hostAddr, hostName: ec.hostName, task: ec.tsk, command: ec.cmd.Name, err: execErr,
		env: execErr.exec.cmd.Environment,
	}
	ec.cmd.Script = tmpl.apply(ec.cmd.Script)
	if _, err = ec.Script(ctx); err != nil {
		log.Printf("[WARN] can't run on-error command for %q, %q: %v", ec.cmd.Name, ec.cmd.Script, err)
	}
}

func (p *Process) anyRemoteCommand(tsk *config.Task) bool {
	for _, cmd := range tsk.Commands {
		if !cmd.Options.Local {
			return true
		}
	}
	return false
}

func (p *Process) infoMessage(cmd config.Cmd, hostAddr, hostName string) string {
	infoMsg := fmt.Sprintf("run command %q on host %q (%s)", cmd.Name, hostAddr, hostName)
	if hostName == "" {
		infoMsg = fmt.Sprintf("run command %q on host %q", cmd.Name, hostAddr)
	}
	if cmd.Options.Local {
		infoMsg = fmt.Sprintf("run command %q on local host", cmd.Name)
	}
	return infoMsg
}

// updateVars sets variables from command output to all commands environment in the same task.
func (p *Process) updateVars(vars map[string]string, cmd config.Cmd, tsk *config.Task) {
	if len(vars) == 0 {
		return
	}

	log.Printf("[DEBUG] set %d variables from command %q: %+v", len(vars), cmd.Name, vars)
	for k, v := range vars {
		for i, c := range tsk.Commands {
			env := c.Environment
			if env == nil {
				env = make(map[string]string)
			}
			if _, ok := env[k]; ok { // don't allow override variables
				continue
			}
			env[k] = v
			tsk.Commands[i].Environment = env
		}
	}
}

// shouldRunCmd checks if the command should be executed on the host. If the command has no restrictions
// (onlyOn field), it will be executed on all hosts. If the command has restrictions, it will be executed
// only on the hosts that match the restrictions.
// The onlyOn field can contain hostnames or IP addresses. If the hostname starts with "!", it will be
// excluded from the list of hosts. If the hostname doesn't start with "!", it will be included in the list
// of hosts. If the onlyOn field is empty, the command will be executed on all hosts.
// It also checks if the command is in the 'only' or 'skip' list, and considers the 'NoAuto' option.
func (p *Process) shouldRunCmd(cmd config.Cmd, hostName, hostAddr string) bool {
	if len(p.Only) > 0 && !stringutils.Contains(cmd.Name, p.Only) {
		log.Printf("[DEBUG] skip command %q, not in only list", cmd.Name)
		return false
	}
	if len(p.Skip) > 0 && stringutils.Contains(cmd.Name, p.Skip) {
		log.Printf("[DEBUG] skip command %q, in skip list", cmd.Name)
		return false
	}
	if cmd.Options.NoAuto && (len(p.Only) == 0 || !stringutils.Contains(cmd.Name, p.Only)) {
		log.Printf("[DEBUG] skip command %q, has noauto option", cmd.Name)
		return false
	}

	if len(cmd.Options.OnlyOn) == 0 {
		return true
	}

	for _, host := range cmd.Options.OnlyOn {
		if strings.HasPrefix(host, "!") { // exclude host
			if hostName == host[1:] || hostAddr == host[1:] {
				log.Printf("[DEBUG] skip command %q, excluded host %q", cmd.Name, host[1:])
				return false
			}
			continue
		}
		if hostName == host || hostAddr == host { // include host
			return true
		}
	}

	log.Printf("[DEBUG] skip command %q, not in only_on list", cmd.Name)
	return false
}

func isLocalHost(hostAddr string) bool {
	pt := strings.Split(hostAddr, ":")
	if len(pt) == 1 {
		return hostAddr == "127.0.0.1" || hostAddr == "localhost"
	}
	if len(pt) == 2 {
		return pt[0] == "127.0.0.1" || pt[0] == "localhost"
	}
	return false
}
