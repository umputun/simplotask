# Spot

Spot is a powerful and easy-to-use tool for effortless deployment and configuration management. It allows users to define a playbook with a list of tasks and targets, where each task consists of a series of commands that can be executed on remote hosts concurrently. Spot supports running scripts, copying files, syncing directories, and deleting files or directories, as well as custom inventory files or inventory URLs.

<div align="center">
  <img class="logo" src="https://github.com/umputun/spot/raw/master/site/spot-bg.png" width="400px" alt="Spot | Effortless Deployment"/>
</div>

## Features

- Define [tasks](#tasks-and-commands) with a list of [commands](#command-types) and the list of [target hosts](#targets).
- Support for remote hosts specified directly or through [inventory](#inventory) files or URLs.
- Everything can be defined in a [simple YAML](#full-playbook-example) or TOML file.
- Run [scripts](#script-execution) on remote hosts and the localhost.
- Built-in [commands](#command-types): script, copy, sync, delete, echo, and wait.
- [Concurrent](#rolling-updates) execution of a task on multiple hosts.
- Ability to wait for a specific condition before executing the next command.
- Customizable environment variables.
- Support for [secrets](#secrets) stored in the [built-in](#built-in-secrets-provider) secrets storage, [Vault](#hashicorp-vault-secrets-provider), [ansible vault](#ansible-vault-secrets-provider) or [AWS Secrets Manager](#aws-secrets-manager-secrets-provider).
- Ability to [override](#command-options) list of destination hosts, ssh username and ssh key file.
- Skip or execute only specific commands.
- Catch errors and execute a command hook on the local host.
- Debug mode to print out the commands to be executed, the output of the commands, and all the other details.
- Dry-run mode to print out the commands to be executed without executing them.
- [Ad-hoc mode](#ad-hoc-commands) to execute a single command on a list of hosts.
- A [single binary](https://github.com/umputun/spot/releases) with no external dependencies.
----

<div align="center">

[![build](https://github.com/umputun/spot/actions/workflows/ci.yml/badge.svg)](https://github.com/umputun/spot/actions/workflows/ci.yml)&nbsp;[![Coverage Status](https://coveralls.io/repos/github/umputun/spot/badge.svg?branch=master)](https://coveralls.io/github/umputun/spot?branch=master)&nbsp;[![Go Report Card](https://goreportcard.com/badge/github.com/umputun/spot)](https://goreportcard.com/report/github.com/umputun/spot)&nbsp;[![Go Reference](https://pkg.go.dev/badge/github.com/umputun/spot.svg)](https://pkg.go.dev/github.com/umputun/spot)&nbsp;[![GitHub release](https://img.shields.io/github/release/umputun/spot.svg)](https://github.com/umputun/spot/releases)
</div>

<details markdown>
  <summary>Screenshots</summary>

- `spot` with playbook `spot.yml`: `spot -p spot.yml -t prod`

![spot-playbook](https://github.com/umputun/spot/raw/master/site/docs/screen-playbook.jpg)

- `spot` with the same playbook in dry mode: `spot -p spot.yml -t prod -v`

![spot-playbook-dry](https://github.com/umputun/spot/raw/master/site/docs/screen-playbook-dry.jpg)

- `spot` ad-hoc command on given hosts: `spot "ls -la /tmp -t dev1.umputun.com -t dev2.umputun.com`

![spot-adhoc](https://github.com/umputun/spot/raw/master/site/docs/screen-adhoc.jpg)
</details>

## Getting Started

- Install Spot by download the latest release from the [Releases](https://github.com/umputun/spot/releases) page.
- Create a configuration file, as shown in the [example below](#full-playbook-example), and save it as `spot.yml`.
- Run Spot using the following command: `spot`. This will execute all the tasks defined in the default `spot.yml` file for the `default` target with a concurrency of 1.
- To execute a specific task, use the `--task` flag: `spot --task=deploy-things`. This will execute only the `deploy-things` task.
- To execute a specific task for a specific target, use the `--task` and `--target` flags: `spot --task=deploy-things --target=prod`. This will execute only the `deploy-things` task for the `prod` target.

<details markdown>
  <summary>Other install methods</summary>

  
**Install from homebrew (macOS)**

```bash
brew tap umputun/apps
brew install umputun/apps/spot
```

_This will install both `spot` and `spot-secrets` binaries._

**Install from deb package (Ubuntu/Debian)**

1. Download the latest version of the package by running: `wget https://github.com/umputun/spot/releases/download/<versiom>/spot_<version>_linux_<arch>.deb` (replace `<version>` and `<arch>` with the actual values).
2. Install the package by running: `sudo dpkg -i spot_<version>_linux_<arch>.deb`

Example for the version 0.14.6 and amd64 architecture:

```bash
wget https://github.com/umputun/spot/releases/download/v0.14.6/spot_v0.14.6_linux_<arch>.deb
sudo dpkg -i spot_v0.14.6_linux_<arch>.deb
```

**Install from rpm package (CentOS/RHEL/Fedora/AWS Linux)**

```bash
wget https://github.com/umputun/spot/releases/download/v<version>/spot_v<version>_linux_<arch>.rpm
sudo rpm -i spot_v<version>_linux_<arch>.rpm
```

**Install from apk package (Alpine)**

```bash
wget https://github.com/umputun/spot/releases/download/<versiom>/spot_<version>_linux_<arch>.apk
sudo apk add spot_<version>_linux_<arch>.apk
```

**Universal installation for Linux and macOS**

Spot provides a universal installation script that can be used to install the latest version of the tool on Linux and macOS.

1. Download the installation script: `wget https://raw.githubusercontent.com/umputun/spot/master/install.sh`
2. Carefully review the script to make sure it is safe.
3. Run the script: `sudo sh install.sh`

The script will detect the OS and architecture and download the correct binary for the latest version of Spot.

If you are brave enough, you can run the script directly from the web, but I'd recommend downloading it first and reviewing it:

```bash
curl -sSfL https://raw.githubusercontent.com/umputun/spot/master/install.sh | sudo sh
```

**Install with go install**

This method requires [Go](https://golang.org/) to be installed on your system.

```bash
go install github.com/umputun/spot/cmd/spot@latest
go install github.com/umputun/spot/cmd/spot-secrets@latest

```

</details>

## Options

Spot supports the following command-line options:

- `-p`, `--playbook=`: Specifies the playbook file for use. Defaults to `spot.yml`. You can also set the environment
  variable `$SPOT_PLAYBOOK` to define the playbook file path.
- `-n`, `--task=`: Specifies task names to execute. The task should be defined in the playbook file. Several tasks can be executed by providing the `--task` flag multiple times, e.g., `-n copy_files -n warmup_cache`.
  If not specified all the tasks will be executed.
- `-t`, `--target=`: Specifies the target name to use for the task execution. The target should be defined in the playbook file and can represent remote hosts, inventory files, or inventory URLs. If not specified, the `default` target will be used. User can pass a hostname, group name, tag or IP instead of the target name for a quick override. Providing the `-t`, `--target` flag multiple times with different targets sets multiple destination targets or multiple hosts, e.g., `-t prod -t dev` or `-t example1.com -t example2.com`.
- `-c`, `--concurrent=`: Sets the number of concurrent hosts to execute tasks. Defaults to `1`, which means hosts will be handled  sequentially.
- `--timeout`: Sets the SSH timeout. Defaults to `30s`. User can also set the environment variable `$SPOT_TIMEOUT` to define the SSH timeout.
- `--ssh-agent`: Enables using the SSH agent for authentication. Defaults to `false`. Users can also set the environment variable `SPOT_SSH_AGENT` to define the value.
- `--forward-ssh-agent`: Enables forwarding of connections from an authentication agent. Defaults to `false`. Users can also set the environment variable `SPOT_FORWARD_SSH_AGENT` to define the value.
- `--shell` - shell for remote ssh execution, default is `/bin/sh`. Users can also set the environment variable `SPOT_SHELL` to define the value.  
- `-i`, `--inventory=`: Specifies the inventory file or URL to use for the task execution. Overrides the inventory file defined in the
  playbook file. Users can also set the environment variable `$SPOT_INVENTORY` to define the default inventory file path or url.
- `-u`, `--user=`: Specifies the SSH user to use when connecting to remote hosts. Overrides the user defined in the playbook file .
- `-k`, `--key=`: Specifies the SSH key for connecting to remote hosts. Overrides the key defined in the playbook file.
- `-s`, `--skip=`: Skips the specified commands during the task execution. Providing the `-s` flag multiple times with different command names skips multiple commands.
- `-o`, `--only=`: Runs only the specified commands during the task execution. Providing the `-o` flag multiple times with different command names runs only multiple commands.
- `-e`, `--env=`: Sets the environment variables to be used during the task execution. Providing the `-e` flag multiple times with different environment variables sets multiple environment variables, e.g., `-e VAR1:VALUE1 -e VAR2:VALUE2`. Values could be taken from the OS environment variables as well, e.g., `-e VAR1:$ENV_VAR1` or `-e VAR1:${ENV_VAR1}`.
- `-E`, `--env-file=`: Sets the environment variables from the file to be used during the task execution. The file can have values from the OS environment variables as well. The default is env.yml. Can also be set with the environment variable `SPOT_ENV_FILE`.
- `--no-color`: disable the colorized output. It can also be set with the environment variable `SPOT_NO_COLOR`.
- `--dry`: Enables dry-run mode, which prints out the commands to be executed without actually executing them.
- `-v`, `--verbose`: Enables verbose mode, providing more detailed output and error messages during the task execution. Setting this flag multiple times increases the verbosity level, i.e., `-vv`.
- `--dbg`: Enables debug mode, providing even more detailed output and error messages during the task execution and diagnostic messages.
- `-h` `--help`: Displays the help message, listing all available command-line options.

## Basic Concepts

- **Playbook** is a YAML or TOML file that defines a list of tasks to be executed on one or more target hosts. Each task consists of a series of commands that can be executed on the target hosts. Playbooks can be used to automate deployment and configuration management tasks.

- **Task** is a named set of commands that can be executed on one or more target hosts. Tasks can be defined in a playbook and executed concurrently on multiple hosts.

- **Command** is an action that can be executed on a target host. Spot supports several built-in commands, including copy, sync, delete, script, echo, and wait. 

- **Target** is a host or group of hosts on which a task can be executed. Targets can be specified directly in a playbook or defined in an inventory file. Spot supports several inventory file formats.

- **Inventory** is a list of targets that can be used to define the hosts and groups of hosts on which a task can be executed. 

## Playbooks

### Full playbook example

```yaml
user: umputun                       # default ssh user. Can be overridden by -u flag or by inventory or host definition
ssh_key: keys/id_rsa                # ssh key
ssh_shell: /bin/bash                # shell to use for remote ssh execution, default is /bin/sh
local_shell: /bin/bash              # shell to use for local execution, default is os shell
inventory: /etc/spot/inventory.yml  # default inventory file. Can be overridden by --inventory flag

# list of targets, i.e. hosts, inventory files or inventory URLs
targets:
  prod:
    hosts: # list of hosts, user, name and port optional. 
      - {host: "h1.example.com", user: "user2", name: "h1"}
      - {host: "h2.example.com", port: 2222}
      # command will be executed on local if host is localhost or 127.0.0.1
      - {host: "localhost", port: 2222}
  staging:
    groups: ["dev", "staging"] # list of groups from inventory file
  dev:
    names: ["devbox1", "devbox2"] # list of server names from inventory file
  all-boxes:
    groups: ["all"] # all hosts from all groups from inventory file

# list of tasks, i.e. commands to execute
tasks:
  - name: deploy-things
    on_error: "curl -s localhost:8080/error?msg={SPOT_ERROR}" # call hook on error
    commands:
      - name: wait
        script: sleep 5s
      
      - name: copy configuration
        copy: {"src": "testdata/conf.yml", "dst": "/tmp/conf.yml", "mkdir": true}

      - name: copy other files
        copy:
          - {"src": "testdata/f1.csv", "dst": "/tmp/things/f1.csv", "recur": true}
          - {"src": "testdata/f2.csv", "dst": "/tmp/things/f2.csv", "recur": true}

      - name: sync things
        sync: {"src": "testdata", "dst": "/tmp/things"}
      
      - name: some command
        script: |
          ls -laR /tmp
          du -hcs /srv
          cat /tmp/conf.yml
          echo all good, 123
      
      - name: delete things
        delete: {"path": "/tmp/things", "recur": true}
      
      - name: show content
        script: ls -laR /tmp

  - name: docker
    commands:
      - name: docker pull and start
        script: |
          docker pull umputun/remark42:latest
          docker stop remark42 || true
          docker rm remark42 || true
          docker run -d --name remark42 -p 8080:8080 umputun/remark42:latest
        env: {FOO: bar, BAR: qux} # set environment variables for the command
      - wait: {cmd: "curl -s localhost:8080/health", timeout: "10s", interval: "1s"} # wait for health check to pass
```

*Alternatively, the playbook can be represented using the TOML format.*

### Simplified playbook example

In some cases, the rich syntax of the full playbook is not needed and can feel over-engineered and even overwhelming. For those situations, Spot supports a simplified playbook format, which is easier to read and write, but also more limited in its capabilities.


```yaml
user: umputun                       # default ssh user. Can be overridden by -u flag or by inventory or host definition
ssh_key: keys/id_rsa                # ssh key
ssh_shell: /bin/bash                # shell to use for remote ssh execution, default is /bin/sh
local_shell: /bin/bash              # shell to use for local execution, default is os shell
inventory: /etc/spot/inventory.yml  # default inventory file. Can be overridden by --inventory flag

targets: ["devbox1", "devbox2", "h1.example.com:2222", "h2.example.com"] # list of host names from inventory and direct host ips

# the actual list of commands to execute
task:
  - name: wait
    script: sleep 5s
  
  - name: copy configuration
    copy: {"src": "testdata/conf.yml", "dst": "/tmp/conf.yml", "mkdir": true}
  
  - name: copy other files
    copy: 
      - {"src": "testdata/f1.csv", "dst": "/tmp/things/f1.csv", "recur": true}
      - {"src": "testdata/f2.csv", "dst": "/tmp/things/f2.csv", "recur": true}
  
  - name: sync things
    sync: {"src": "testdata", "dst": "/tmp/things"}
  
  - name: some command
    script: |
      ls -laR /tmp
      du -hcs /srv
      cat /tmp/conf.yml
      echo all good, 123
  
  - name: delete things
    delete: {"path": "/tmp/things", "recur": true}
  
  - name: show content
    script: ls -laR /tmp

  - name: docker pull and start
    script: |
      docker pull umputun/remark42:latest
      docker stop remark42 || true
      docker rm remark42 || true
      docker run -d --name remark42 -p 8080:8080 umputun/remark42:latest
    env: {FOO: bar, BAR: qux} # set environment variables for the command
    
  - wait: {cmd: "curl -s localhost:8080/health", timeout: "10s", interval: "1s"} # wait for health check to pass

```

**For more examples see [.examples](https://github.com/umputun/spot/tree/master/.examples) directory.**

### Playbook Types

Spot supports two types of playbooks: full and simplified. Both can be represented in either YAML or TOML format. The full playbook is more powerful and flexible but also more verbose and complex. The simplified playbook, on the other hand, is easier to read and write but has more limited capabilities.

Here are the main differences between the two types of playbooks:

- The full playbook supports multiple target sets, while the simplified playbook only supports a single target set. In other words, the full playbook can execute the same set of commands on multiple environments, with each environment defined as a separate target set. The simplified playbook can execute the same set of commands in just one environment.
- The full playbook supports multiple tasks, while the simplified playbook only supports a single task. This means that the full playbook can execute multiple sets of commands, whereas the simplified playbook can only execute one set of commands.
- The full playbook supports various target types, such as `hosts`, `groups`, and `names`, while the simplified playbook only supports a single type, which is a list of names or host addresses. See the [Targets](#targets) section for more details.
- The simplified playbook does not support task-level `on_error` field, while the full playbook does. See the [Task details](#tasks-and-commands) section for more information.
- The full playbook also supports task-level `user` field, which allows setting the SSH user to use when connecting to remote hosts for the particular task.
- The simplified playbook also has `target` field (in addition to `targets`) that allows setting a single host/name only. This is useful when users want to run the playbook on a single host only. The full playbook does not have this field.

Both types of playbooks support the remaining fields and options.

## Tasks and Commands

Each task consists of a list of commands that will be executed on the remote host(s). The task can also define the following optional fields:

- `on_error`: specifies the command to execute on the local host (the one running the `spot` command) in case of an error. The command can use the `{SPOT_ERROR}` variable to access the last error message. Example: `on_error: "curl -s localhost:8080/error?msg={SPOT_ERROR}"`
- `user`: specifies the SSH user to use when connecting to remote hosts. Overrides the user defined in the top section of the playbook file for the specified task.
- `targets` - list of target names, groups, tags, or host addresses to execute the task on. Command line `-t` flag can be used to override this field. The `targets` field may include variables. For more details see [Dynamic targets](#dynamic-targets) section.

*Note: these fields are supported in the full playbook type only*

All tasks are executed sequentially on a given host, one after another. If a task fails, the execution of the playbook will stop and the `on_error` command will be executed on the local host, if defined. Every task has to have `name` field defined, which is used to identify the task everywhere. Playbook with a missing `name` field will fail to execute immediately. Duplicate task names are not allowed either.

### Relative paths resolution

Relative path resolution is a frequent issue in systems that involve file references or inclusion. Different systems handle this in various ways. Spot uses a widely-adopted method of resolving relative paths based on the current working directory of the process. This means that if you run Spot from different directories, the way relative paths are resolved will change. In simpler terms, Spot doesn't resolve relative paths according to the location of the playbook file itself.

This approach is intentional to prevent confusion and make it easier to comprehend relative path resolution. Generally, it's a good practice to run Spot from the same directory where the playbook file is located when using relative paths. Alternatively, you can use absolute paths for even better results.

### Command Types

Spot supports the following command types:

#### `script`

Can be any valid shell script. The script will be executed on the remote host(s) using SSH, inside a shell.

```yaml
script: |
  ls -laR /tmp
  du -hcs /srv
  cat /tmp/conf.yml
  echo all good, 123
```

Read more about YAML multiline string formatting on [yaml-multiline.info](https://yaml-multiline.info/) and this [stackoverflow post](https://stackoverflow.com/questions/3790454/how-do-i-break-a-string-in-yaml-over-multiple-lines).

#### `copy`

Copies a file from the local machine to the remote host(s). If `mkdir` is set to `true` the command will create the destination directory if it doesn't exist, the same as `mkdir -p` in bash. The command also supports glob patterns in `src` field.

Copy command performs a quick check to see if the file already exists on the remote host(s) with the same size and modification time,
and skips the copy if it does. This option can be disabled by setting `force: true` flag. Another option is `exclude` which allows to specify a list of files to exclude to be copied. 


```yaml
- name: copy file with mkdir
  copy: {"src": "testdata/conf.yml", "dst": "/tmp/conf.yml", "mkdir": true}

- name: copy files with glob
  copy: {"src": "testdata/*.csv", "dst": "/tmp/things"}

- name: copy files with glob and exclude
  copy: {"src": "testdata/*.yml", "dst": "/tmp/things", "exclude": ["conf.dist.yml"]}

- name: copy files with force flag
  copy: {"src": "testdata/*.csv", "dst": "/tmp/things", "force": true}
```

Copy also supports list format to copy multiple files at once:

```yaml
- name: copy files with glob
  copy:
    - {"src": "testdata/*.csv", "dst": "/tmp/things"}
    - {"src": "testdata/*.yml", "dst": "/tmp/things"}
```

Copy file and making it executable is also supported:

```yaml
- name: copy file and make it executable
  copy:
    - {"src": "testdata/script.sh", "dst": "/tmp/script.sh", "chmod+x": true}
```


#### `sync`

Synchronises directory from the local machine to the remote host(s). Optionally supports deleting files on the remote host(s) that don't exist locally with `"delete": true` flag. Another option is `exclude` which allows to specify a list of files to exclude from the sync.

```yaml
- name: sync directory
  sync: {"src": "testdata", "dst": "/tmp/things"}

- name: sync directory with delete
  sync: {"src": "testdata", "dst": "/tmp/things", "delete": true}

- name: sync directory with exclude
  sync: {"src": "testdata", "dst": "/tmp/things", "exclude": ["*.txt", "*.yml"]}
  
```  

Sync also supports list format to sync multiple paths at once.

#### `delete`

Deletes a file or directory on the remote host(s), optionally can remove recursively. 

```yaml
- name: delete file
  delete: {"path": "/tmp/things.csv"}
  
- name: delete directory recursively
  delete: {"path": "/tmp/things", "recur": true}
  
- name: delete directory recursively with exclude
  delete: {"path": "/tmp/things", "recur": true, "exclude": ["*.txt", "*.yml"]}
```

Delete also supports a list format to remove multiple paths at once.

#### `wait`

Waits for the specified command to finish on the remote host(s) with 0 error code. This command is useful when a user needs to wait for a service to start before executing the next command. Allows to specify the timeout as well as check interval.

```yaml
- name: wait for service to start
  wait: {"cmd": "curl -s --fail localhost:8080", "timeout": "30s", "interval": "1s"}
```

#### `echo`

Prints the specified message to the console. This command is useful for debugging purposes and also to print the value of variables to the console.

```yaml
- name: print message
  echo: "hello world"
- name: print variable
  echo: $some_var
```

### Command options

Each command type supports the following options:

- `ignore_errors`: if set to `true` the command will not fail the task in case of an error.
- `no_auto`: if set to `true` the command will not be executed automatically, but can be executed manually using the `--only` flag.
- `local`: if set to `true` the command will be executed on the local host (the one running the `spot` command) instead of the remote host(s).
- `sudo`: if set to `true` the command will be executed with `sudo` privileges. This option is not supported for `sync` command type but can be used with any other command type.
- `only_on`: allows to set a list of host names or addresses where the command will be executed. For example, `only_on: [host1, host2]` will execute a command on `host1` and `host2` only. This option also supports reversed conditions, so if a user wants to execute a command on all hosts except some, `!` prefix can be used. For example, `only_on: [!host1, !host2]` will execute a command on all hosts except `host1` and `host2`. 

example setting `ignore_errors`, `no_auto` and `only_on` options:

```yaml
  commands:
      - name: wait
        script: sleep 5s
        options: {ignore_errors: true, no_auto: true, only_on: [host1, host2]}
```

The same options can be set for the whole task as well. In this case, the options will be applied to all commands in the task but can be overridden for a specific command. Pls note: the command option cannot reset the boolean options that were set for the task. This limitation is due to the way the default values are set.

```yaml
  - name: deploy-things
    on_error: "curl -s localhost:8080/error?msg={SPOT_ERROR}" # call hook on error
    options: {ignore_errors: true, no_auto: true, only_on: [host1, host2]}
    commands:
      - name: wait
        script: sleep 5s
```

### Command conditionals

`cond`: defines a condition for the command to be executed. The condition is a valid shell command that will be executed on the remote host(s) and if it returns 0, the primary command will be executed. For example, `cond: "test -f /tmp/foo"` will execute the primary script command only if the file `/tmp/foo` exists. The condition can be reversed by adding `!` prefix, i.e. `! test -f /tmp/foo` will pass only if the file `/tmp/foo` doesn't exist.

example installing curl package if not installed already:

```yaml
  - name: "install curl"
    script: "yum install curl -y"
    options: {sudo: true}
    cond: "! command -v curl"
```

currently conditions can be used with `script` and `echo` command types only.

### Deferred actions (`on_exit`)

Each command may have `on_exit` parameter defined. It allows executing a command on the remote host after the task with all commands is completed. The command is called regardless of the task's exit code.

This is useful in several scenarios:

- a temporary script copied to the remote host and executed and should be removed after execution with `on_exit: "rm -fv /tmp/script.sh"`
- a service should be restarted after the new version is deployed with `on_exit: "systemctl restart myservice"`


```yaml
  - name: "copy script"
    copy: {src: "testdata/script.sh", "dst": "/tmp/script.sh", "chmod+x": true}
    on_exit: "rm -fv /tmp/script.sh" # register deferred action to remove script.sh after execution
  - name: "run script"
    script: "/tmp/script.sh"
```

In the example above, the `script.sh` is copied to the remote host, executed, and removed after completion of the task.


### Script Execution

Spot allows executing scripts on remote hosts, or locally if `options.local` is set to true. Scripts can be executed in two different ways, depending on whether they are single-line or multi-line scripts.

**Single-line Script Execution**

For single-line scripts, they are executed directly inside the shell with the optional parameters set to the command line. For example:

```yaml
  commands:
      - name: some command
        script: ls -laR /tmp
        env: {FOO: bar, BAR: qux} 
```        
this will be executed as: `FOO='bar' BAR='qux'ls -laR /tmp FOO=bar BAR=qux` inside the shell on the remote host(s), i.e. `sh -c "FOO='bar' BAR='qux'ls -laR /tmp FOO=bar BAR=qux"`.

**Multi-line Script Execution**

For multi-line scripts, Spot creates a temporary script containing all the commands, uploads it to the remote host (or keeps it locally if `options.local` is set to true), and executes the script. Environment variables are set inside the script, allowing the user to create complex scripts that include setting variables, conditionals, loops, and other advanced functionality. Scripts run with "set -e" to fail on error. For example:

```yaml
commands:
  - name: multi_line_script
    script: |
      touch /tmp/file1
      echo "Hello World" > /tmp/file2
      echo "Executing loop..."
      for i in {1..5}; do
        echo "Iteration $i"
      done
      echo "All done! $FOO $BAR
    env: {FOO: bar, BAR: qux}
```

this will create a temporary script on the remote host(s) with the following content and execute it:

```bash
#!/bin/sh
set -e
export FOO='bar'
export BAR='qux'
touch /tmp/file1
echo "Hello World" > /tmp/file2
echo "Executing loop..."
for i in {1..5}; do
  echo "Iteration $i"
done
echo "All done! $FOO $BAR"
```

By using this approach, Spot enables users to write and execute more complex scripts, providing greater flexibility and power in managing remote hosts or local environments.

Users can also set any custom shebang for the script by adding `#!` at the beginning of the script. For example:

```yaml
commands:
  - name: multi_line_script
    script: |
      #!/bin/bash
      touch /tmp/file1
      echo "Hello World" > /tmp/file2

```

### Passing variables from one script command to another

The spot allows passing variables from one command to another. This feature is especially useful when a command, often a script, sets a variable, and the subsequent command requires this variable. For instance, if one command creates a file and the file name is needed in another command. To pass these variables, a user must use the conventional shell's export directive in the initial script command. Subsequently, all variables exported in this initial command will be accessible in the following commands.

For example:

```yaml
commands:
  - name: first command
    script: |
      export FILE_NAME=/tmp/file1
      touch $FILE_NAME
  - name: second command
    script: |
      echo "File name is $FILE_NAME"
  - name: third command
    copy: {src: $FILE_NAME, dest: /tmp/file2}
```

Sometimes, exporting variables is not possible or not desired. For such cases, Spot allows to register variables explicitly using the `register` option.

For example:

```yaml
commands:
  - name: first command
    script: |
      FILE_NAME=/tmp/file1
      touch $FILE_NAME
      ANOTHER_VAR=foo
    register: [FILE_NAME, ANOTHER_VAR]
      
  - name: second command
    script: |
      echo "File name is $FILE_NAME, var is $ANOTHER_VAR"
      
  - name: third command
    copy: {src: $FILE_NAME, dest: /tmp/file2}
```

Another unique feature of the registered variables is that they can be used not only in the subsequent commands for the current task but also in the subsequent tasks. This allows users to pass variables between tasks. In other words, the registered variables are populated to the environment of all the tasks in the playbook, automatically.

example:

```yaml
tasks:
  - name: set_register_var
    commands:
      - name: some command
        script: |
          echo good command 1
          len=$(echo "file content" | wc -c)
        register: [len]

  - name: use_register_var
    commands:
      - name: some command
        script: |
          echo "len: $len"
```

### Setting environment variables

Environment variables can be set with `--env` / `-e` cli option. For example: `-e VAR1:VALUE1 -e VAR2:VALUE2`. Environment variables can also be set in the environment file (default `env.yml` can be changed with `--env-file` / `-E` cli flag). For example:
```yaml
vars:  
  VAR1: VALUE1
  VAR2: VALUE2
```
Environment variables can be used in the playbook file with the expected syntax: `$VAR_NAME` or `${VAR_NAME}`. For example:

```yaml
commands:
  - name: some command
    script: echo $VAR1
  - name: another command
    copy: {"src": "testdata/*.csv", "dst": "$VAR2"}
```

In case of a conflict between environment variables set in the environment file and the cli, the cli variables will take precedence.

## Targets

Targets are used to define the remote hosts to execute the tasks on. Targets can be defined in the playbook file or passed as a command-line argument. The following target types are supported:

- `hosts`: a list of destination host names or IP addresses, with optional port and username, to execute the tasks on. Example: `hosts: [{host: "h1.example.com", user: "test", name: "h1}, {host: "h2.example.com", "port": 2222}]`. If no user is specified, the user defined in the top section of the playbook file (or override) will be used. If no port is specified, port 22 will be used.
- `groups`: a list of groups from inventory to use. Example: `groups: ["dev", "staging"}`. A special group `all` combines all the groups.
- `tags`: a list of tags from inventory to use. Example: `tags: ["tag1", "tag2"}`.
- `names`: a list of host names from inventory to use. Example: `names: ["host1", "host2"}`.

All the target types can be combined, i.e. `hosts`, `groups`, `tags`, `hosts` and `names` all can be used together in the same target. To avoid possible duplicates, the final list of hosts is deduplicated by the host+ip+user. 

example of targets set in the playbook file:

```yaml
targets:
  prod:
    hosts: [{host: "h1.example.com", user: "test"}, {"h2.example.com", "port": 2222, name: "h2"}]
  staging:
    groups: ["staging"]
  dev:
    groups: ["dev", "staging"]
    names: ["host1", "host2"]
  all-servers:
    groups: ["all"]

tasks:
  - name: task1
    targets: ["dev", "host3.example.com:2222"]
    commands:
      - name: command1
        script: echo "Hello World"
```

*Note: All the target types are available in the full playbook file only. The simplified playbook file only supports a single, anonymous target type combining `hosts` and `names` together.*

```yaml
targets: ["host1", "host2", "host3.example.com", "host4.example.com:2222"]
```

in this example, the playbook will be executed on hosts named `host1` and `host2` from the inventory and on hosts `host3.example.com` with port `22` and `host4.example.com` with port `2222`.

### Target overrides

There are several ways to override or alter the target defined in the playbook file via command-line arguments:

- `--inventory` set hosts from the provided inventory file or url. Example: `--inventory=inventory.yml` or `--inventory=http://localhost:8080/inventory`.
- `--target` set groups, names, tags from inventory or direct hosts to run the playbook on. Example: `--target=prod` (will run on all hosts in group `prod`) or `--target=example.com:2222` (will run on host `example.com` with port `2222`). User name can be provided as a part of the direct target address as well, i.e. `--target=user2@example.com:2222`
- `--user` set the ssh user to run the playbook on remote hosts. Example: `--user=test`.
- `--key` set the ssh key to run the playbook on remote hosts. Example: `--key=/path/to/key`.

### Target selection

The target selection is done in the following order:

- if `--target` is set, it will be used.
  - first Spot will try to match on target name in the playbook file.
  - if no match is found, Spot will try to match on the group name in the inventory file.
  - if no match is found, Spot will try to match on tags in the inventory file.
  - if no match is found, Spot will try to match on hostname in the inventory file.
  - if no match is found, Spot will try to match on host address in the playbook file.
  - if no match is found, Spot will use it as a host address.
- if `--target` is not set, Spot will try to check it `targets` list for the task. If set, it will use it following the same logic as above.
- and finally, Spot will assume the `default` target.

### Dynamic targets

Spot offers support for dynamic targets, allowing the list of targets to be defined dynamically using variables. This feature becomes particularly useful when users need to ascertain a destination address within one task, and subsequently use it in another task. Here is an illustrative example:

```yaml
tasks:
  - name: get host
    targets: ["default"]
    script: |
      export thehost=$(curl -s http://example.com/next-host)
    options: {local: true}
    
  - name: run on host
    targets: ["$thehost"]
    script: |
      echo "doing something on $thehost"
```

In this example, the host address is initially fetched from http://example.com/next-host. Following this, the task "run on host" is executed on the host that was just identified. This ability to use dynamic targets proves beneficial in a variety of scenarios, especially when the list of hosts is not predetermined.

A practical use case for dynamic targets arises during the provisioning of a new host, followed by the execution of commands on it. Since the IP address of the new host isn't known beforehand, dynamic retrieval becomes essential.

_The reason the first task specifies `targets: ["default"]` is because Spot requires some target to execute a task. In this case, all commands in "get host" tasks are local and won't be invoked on a remote host. The `default` target is utilized by Spot if no alternative target is specified via the command line._

### Inventory 

The inventory file is a simple yml (or toml) that can represent a list of hosts or a list of groups with hosts. In case if both groups and hosts are defined, the hosts will be merged with groups and will add a new group named `hosts`.

By default, inventory is loaded from the file/url set in `SPOT_INVENTORY` environment variable. This is the lowest priority and can be overridden by `inventory` from the playbook (next priority) and `--inventory` flag (highest priority)
. 
This is an example of the inventory file with groups

```yaml
groups:
  dev:
    - {host: "h1.example.com", name: "h1", tags:["us-east1", "vpc-1234567"]}
    - {host: "h2.example.com", port: 2233, name: "h2"}
    - {host: "h3.example.com", user: "user1"}
    - {host: "h4.example.com", user: "user2", name: "h4"}
  staging:
    - {host: "h5.example.com", port: 2233, name: "h5"}
    - {host: "h6.example.com", user: "user3", name: "h6"}
```

- host: the hostname or IP address of the remote host.
- port: the ssh port of the remote host. Optional, default is 22.
- user: the ssh user of the remote host. Optional, default is the user defined in the playbook file or `--user` flag.
- name: the name of the remote host. Optional.
- tags: the list of tags of the remote host. Optional.

In case if port is not defined, the default port 22 will be used. If the user is not defined, the playbook's user will be used. 

This is an example of the inventory file with hosts only (no groups)

```yaml
hosts:
  - {host: "hh1.example.com", name: "hh1"}
  - {host: "hh2.example.com", port: 2233, name: "hh2", user: "user1"}
  - {host: "h2.example.com", port: 2233, name: "h2", tags:["us-east1", "vpc-1234567"]}
  - {host: "h3.example.com", user: "user1", name: "h3"}
  - {host: "h4.example.com", user: "user2", name: "h4"}
```
This format is useful when you want to define a list of hosts without groups.

In each case, inventory is automatically merged and a special group `all` will be created that contains all the hosts.

*Alternatively, the inventory can be represented using the TOML format.*

### Export 

Spot supports exporting all the destinations from selected/matched targets to the file or stdout. This is useful when users want to use the same hosts/ports/server-names/etc in other systems. By default, with `--gen` option, Spot will export to stdout in json format. To export to the file, `--gen.output=/path/to/file` option can be used.

This exported list of destinations can be consumed by another system, but practically it will require some conversion from the spot's json to the format that is supported by the system. This can be addressed by injecting [`jq`](https://stedolan.github.io/jq/) into the mix but spot  also offers a better solution - templating with the standard go templates. To turn this feature on, `--gen.template=/path/to/template` option can be used.

Example of the template file, showing all the fields that can be used:

```
{{- range .}}
"Name": "{{.Name}}"
"Host:Port": "{{.Host}}:{{.Port}}"
"User": "{{.User}}"
"Tags": [{{range .Tags}}"{{.}}"{{end}}]
{{- end -}}
```

_for more info see [go templates](https://pkg.go.dev/text/template)_


## Runtime variables

Spot supports runtime variables that can be used in the playbook file. The following variables are supported:

- `{SPOT_REMOTE_HOST}`: The remote hostname or IP address with port.
- `{SPOT_REMOTE_ADDR}`: The remote hostname or IP address.
- `{SPOT_REMOTE_PORT}`: The remote port.
- `{SPOT_REMOTE_NAME}`: The remote custom name, set in inventory or playbook as `name`.
- `{SPOT_REMOTE_USER}`: The remote username.
- `{SPOT_COMMAND}`: The command name.
- `{SPOT_TASK}`: The task name.
- `{SPOT_ERROR}`: The error message, if any.

Variables can be used in the following places: `script`, `copy`, `sync`, `delete`, `wait` and `env`, for example:

```yaml
tasks:
    name: deploy-things
    commands:
      - name: copy configuration
        copy: {"src": "{SPOT_REMOTE_HOST}/conf.yml", "dst": "/tmp/conf.yml", "mkdir": true}
      - name: sync things
        sync: {"src": "testdata", "dst": "/tmp/{SPOT_TASK}/things"}
      - name: some command
        script: |
          ls -laR /tmp/${SPOT_COMMAND}
        env: { FOO: bar, BAR: "{SPOT_COMMAND}-blah" }
      - name: delete things
        delete: {"loc": "/tmp/things/{SPOT_REMOTE_USER}", "recur": true}

```

## Ad-hoc commands

Spot supports ad-hoc commands that can be executed on the remote hosts. This is useful when all is needed is to execute a command on the remote hosts without creating a playbook file. This command is optionally passed as a first argument, i.e. `spot "ls -la /tmp"` and usually accompanied by the `--target=<host>` (`-t <host>`) flags. Example: `spot "ls -la" -t h1.example.com -t h2.example.com`.

All other overrides can be used with ad-hoc commands as well, for example `--user`and `--key` to specify the user and sshkey to use when connecting to the remote hosts. By default, Spot will use the current user and the default ssh key. Inventory can be passed to such commands as well, for example `--inventory=inventory.yml`.

Adhoc commands always sets `verbose` to `true` automatically, so the user can see the output of the command.


## Rolling Updates

Spot supports rolling updates, which means that the tasks will be executed on the hosts one by one, waiting for the previous host to finish before starting the next one. This is useful when you need to update a service running on multiple hosts but want to avoid downtime. To enable rolling updates, use the `--concurrent=N` flag when running the `spot` command. `N` is the number of hosts to execute the tasks concurrently. Example: `spot --concurrent=2`. In addition, the user can use a built-in `wait` command to wait for a service to start before executing the next command. See the [Command Types](#command-types) section for more details. Practically, the user will have a task with a series of commands, where the last command will wait for the service to start by running a command like `curl -s --fail localhost:8080` and then the task will be executed on the next host.

## Secrets

Spot supports secrets, which are encrypted string values that can be used in the playbook file. This feature is useful for storing sensitive information, such as passwords or API keys. Secrets are encrypted, and their values are decrypted at runtime. Spot supports three types of secret providers: built-in, Hashicorp Vault, and AWS Secrets Manager. Other providers can be added by implementing the `SecretsProvider` interface with a single `GetSecrets` method.

Using secrets is simple. First, users need to define a secret provider in the command line options or environment variables. Then, users can add secrets to any command in the playbook file by setting `options.secrets`, as shown in the following example:

```yaml
tasks:
  - name: access sensitive data
    commands:
      - name: read api response
        script: |
          curl -s -u ${user}:${password} https://api.example.com  
          curl https://api.example.com -H "Authorization: Bearer ${token}"
        options:
          secrets: [user, password, token]
```

In this case secrets for keys `user`, `password` and `token` will be read from the secrets provider, decrypted at runtime, and passed to the command in the environment. Please note: if a user runs `spot` with the `--verbose` or `--dbg` flag, the secrets will be replaced with `****` in the output. This is done to prevent secrets from being displayed or logged.


Sometimes, users may want to use the same set of secrets in multiple commands. To avoid repeating the secrets in each command, users can set `secrets` at the task level, as shown in the following example:

```yaml
tasks:
  - name: access sensitive data
    commands:
      - name: read api response
        script: |
          curl -s -u ${user}:${password} https://api.example.com  
          curl https://api.example.com -H "Authorization: Bearer ${token}"
    options:
      secrets: [user, password, token]
```


### Built-in Secrets Provider

Spot includes a built-in secrets provider that can be used to store secrets in SQLite, MySQL, or Postgresql databases. The provider can be configured using the following command line options or environment variables:

- `--secrets.provider=spot`: selects the built-in secret`s provider.
- `--secrets.conn` or `$SPOT_SECRETS_CONN`: the connection string to the database
  - sqlite: `file:///path/to/database.db` or `/path/to/database.sqlite` or `/path/to/database.db`, default: `spot.db`
  - mysql: `user:password@tcp(host:port)/dbname`
  - postgresql: `postgres://user:password@host:port/database?option1=value1&option2=value2`
- `--secrets.key` or `$SPOT_SECRETS_KEY`: the encryption key to use for decrypting secrets.

If `spot` provider is selected, the table `spot_secrets` will be created in the database. The table has the following columns: `skey` and `sval`. The `skey` column is the secret key, and the `sval` column is the encrypted secret value. The `skey` column is indexed for faster lookups. It is recommended to use application-specific prefixes for the secret keys, for example, `system-name/service-name/secret-key`. This will allow to use the same database for multiple applications without conflicts.

The built-in secrets provider uses strong cryptography techniques to ensure the safety of your secrets. Below is a summary of the security methods employed:

- **Argon2 key derivation**: The Argon2 key derivation function (argon2.IDKey) is used to derive a 32-byte key from the provided user key and a randomly generated salt. This function is memory-hard and designed to be resistant to GPU-based attacks, providing increased security for your secrets.
- **NaCl SecretBox encryption**: Secrets are encrypted and decrypted using the [NaCl SecretBox](https://pkg.go.dev/golang.org/x/crypto/nacl/secretbox) package, which provides authenticated encryption with additional data. It uses XSalsa20 for encryption and Poly1305 for authentication, ensuring the integrity and confidentiality of the stored secrets.
- **Random nonces and salts**: Spot generates random nonces for each encryption operation and random salts for each key derivation operation. These values are produced using the crypto/rand package, which generates cryptographically secure random numbers.
- **Base64 encoding**: Encrypted secret values are stored in the database as Base64 encoded strings, which provides a safe and compact way to represent binary data in text form.

These methods work together to provide a robust and secure way to manage secrets in Spot. By using the built-in secrets provider, users can be confident that their sensitive data is securely stored and protected from unauthorized access.

### Hashicorp Vault Secrets Provider

Spot supports Hashicorp Vault as a secrets provider. To use it, a user needs to set the following command line options or environment variables:

- `--secrets.provider=vault`: selects the Hashicorp Vault secrets provider.
- `--secrets.vault.token` or `$SPOT_SECRETS_VAULT_TOKEN`: the Vault token to use for authentication.
- `--secrets.vault.url` or `$SPOT_SECRETS_VAULT_URL`: the Vault server url.
- `--secrets.vault.path` or `$SPOT_SECRETS_VAULT_PATH`: the path to the secrets in Vault.

### AWS Secrets Manager Secrets Provider  

Spot supports AWS Secrets Manager as a secrets provider. To use it, a user needs to set the following command line options or environment variables:

- `--secrets.provider=aws`: selects the AWS Secrets Manager secrets provider.
- `--secrets.aws.region` or `$SPOT_SECRETS_AWS_REGION`: the AWS region to use for authentication.
- `--secrets.aws.access-key` or `$SPOT_SECRETS_AWS_ACCESS_KEY`: the AWS access key to use for authentication.
- `--secrets.aws.secret-key` or `$SPOT_SECRETS_AWS_SECRET_KEY`: the AWS secret key to use for authentication.

note: by default, the AWS Secrets Manager secrets provider will use the default AWS credential. This means that the provider will use the credentials from the environment variables `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`. 

### Ansible Vault Secrets Provider

Spot gives the ability to use full encrypted `YAML` files by [ansbile-vault](https://docs.ansible.com/ansible/latest/cli/ansible-vault.html)

`--secrets.provider=ansible-vault`: selects the Ansible Vault secrets provider.
`--secrets.ansible.path` or `$SPOT_SECRETS_ANSIBLE_PATH` path to the ansible-vault file
`--secrets.ansible.secret` or `$SPOT_SECRETS_ANSIBLE_SECRET` secret string for decrypting ansible-vault file

note: encrypted values in the vault should be in the following format `key[string]:value[string]` without nested `lists` and `maps`.

### Managing Secrets with `spot-secrets`

Spot provides a simple way to manage secrets for builtin providers using the `spot-secrets` utility. This command can be used to set, delete, get, and list secrets in the database. 

- `spot-secrets set <key> <value>`: sets the secret value for the specified key.
- `spot-secrets get <key>`: gets the secret value for the specified key.
- `spot-secrets delete <key>`: deletes the secret value for the specified key.
- `spot-secrets list`: lists all the secret keys in the database.

```
Usage:
  spot-secrets [OPTIONS] <command>

Application Options:
  -k, --key=  key to use for encryption/decryption [$SPOT_SECRETS_KEY]
  -c, --conn= connection string to use for the secrets database (default: spot.db) [$SPOT_SECRETS_CONN]
      --dbg   debug mode

Help Options:
  -h, --help  Show this help message

Available commands:
  del   delete a secret
  get   retrieve a secret
  list  list secrets keys
  set   add a new secret

```

## Why Spot?

Spot is simple. It only has a few basic commands with a very limited set of options and flags. The playbook is just a list of commands to run, plus a list of remote targets to apply those commands against. Each command is made to be as intuitive and as direct as possible. Despite its simplicity, Spot is surprisingly powerful and can help get things done. This tool was built out of frustration with the complexity of similar tools. All I wanted was something that is simple, easy to use, easy to understand, and capable of handling most of the usual deployment tasks. I didn't want to have to check the documentation or resort to googling every time I used it. Spot is the result of that effort.

<details markdown>
  
  <summary>Why Spot? Is it replacing Ansible?</summary>
  
Spot is designed to provide a simple, efficient, and flexible solution for deployment and configuration management. 
It addresses the need for a tool that is easy to set up and use, while still offering powerful features for managing infrastructure.

Below are some of the reasons why you should consider using Spot:

1. **Keeps it simple**: Spot concentrates on one task and one task only - deploying things with minimal headache. It doesn't try to solve all the problems in the universe; instead, it offers a focused and sufficient set of features to address the majority of use cases without unnecessary complexity.
2. **Conceptual simplicity and predictability**: Spot embraces simplicity in its design and execution. Rather than being declarative, tasks contain a direct list of straightforward commands to achieve the desired outcome. This approach ensures that Spot is highly predictable, as it strictly follows the user's instructions without attempting to interpret or guess their intentions. This makes it easier for users to understand and control the deployment process.
3. **User-friendly**: Spot prioritizes user-friendliness by providing a limited and intuitive set of command line options, making it easy to get started with deploying projects. Additionally, Spot uses well-known YAML or TOML formats for its playbook and inventory files. The minimalistic structure of these files enhances readability and makes them more approachable for users who want to focus on deploying their projects without getting bogged down in complex syntax or unnecessary details. For simpler use cases, Spot also offers a simplified playbook format that further streamlines the deployment process.
4. **Full control**: Spot gives users full control over their deployments. Users can select any set of tasks and hosts, and even limit which commands are executed. Spot provides a dry mode that allows users to preview the changes that will be made before executing the playbook. The verbose modes provide many details to help users understand what's going on during the deployment process, while the debug mode gives maximum detailed logs for users who need to investigate deeper. 
5. **Safe and secure**: Spot prioritizes security, offering seamless integration with various secret vault solutions, as well as providing a built-in option. This ensures that sensitive information is handled securely, giving users peace of mind while managing their infrastructure.
6. **Flexible and extensible**: Spot is designed to adapt to various deployment and configuration scenarios, managing different targets like production, staging, and development environments. It supports executing tasks on remote hosts directly or through inventory files and URLs, integrating with existing inventory management solutions. Spot also allows for custom script execution on remote hosts and offers built-in commands for common operations, enabling the creation of tailored workflows for deployment and configuration management.
7. **Concurrent Execution and Rolling Updates**: Spot supports concurrent execution of tasks, speeding up deployment and configuration processes by running on multiple hosts simultaneously. This is especially helpful when managing large-scale infrastructure or when time is of the essence. Spot also allows for rolling updates with user-defined wait commands, ensuring smooth and controlled deployment of changes across the infrastructure.
8. **Customizable**: Spot offers various command-line options and environment variables that allow users to tailor its behavior to their specific requirements. Users can easily modify the playbook file, task, target, and other parameters, as well as control the execution flow by skipping or running specific commands.
9. **Lightweight**: Spot is a lightweight tool, written in Go, that does not require heavy dependencies or a complex setup process. It can be easily installed and run on various platforms, making it an ideal choice for teams looking for a low-overhead solution for deployment and configuration management.
10. **Ready-to-use binaries and packages**: Spot is available as ready-to-use binaries and packages for various platforms, including Linux, macOS, and Windows. Users can download and install the appropriate package for their platform, making it easy to get started with Spot without having to build from source. Spot provides binaries for both x86, arm, and arm64 architectures, as well as rpm, deb and apk packages for Linux users.

In conclusion, Spot is a powerful and easy-to-use tool that simplifies the process of deployment and configuration management while offering the flexibility and extensibility needed to cater to various use cases. 


### Is it replacing Ansible?

Spot is not designed as a direct replacement for Ansible; however, in certain use cases, it can address the same challenges effectively. While both tools can be used for deployment and configuration management, there are some key differences between them:

- **Complexity**: Ansible is a more feature-rich and mature tool, offering a wide range of modules and plugins that can automate many different aspects of infrastructure management. Spot, on the other hand, is designed to be simple and lightweight, focusing on a few core features to streamline the deployment and configuration process.
- **Learning Curve**: Due to its simplicity, Spot has a lower learning curve compared to Ansible. It's easier to start with Spot, making it more suitable for smaller projects or teams with limited experience in infrastructure automation. Ansible, while more powerful, can be more complex to learn and configure, especially for newcomers. 
- **Customization**: While both tools offer customization options, Ansible has a more extensive set of built-in modules and plugins that can handle a wide range of tasks out of the box. Spot, in contrast, relies on custom scripts and a limited set of built-in commands for its functionality, which might require more manual configuration and scripting for certain use cases.
- **Community and Ecosystem**: Ansible has a large and active community, as well as a vast ecosystem of roles, modules, and integrations. This can be beneficial when dealing with common tasks or integrating with third-party systems. Spot, being a smaller and simpler tool, doesn't have the same level of community support or ecosystem.
- **Ease of installation and external dependencies**: One of the most significant benefits of Spot is that it has no dependencies. Being written in Go, it is compiled into a single binary that can be easily distributed and executed on various platforms. This eliminates needing to install or manage any additional software, libraries, or dependencies to use Spot. Ansible, on the other hand, is written in Python and requires Python to be installed on both the control host (where Ansible is run) and the managed nodes (remote hosts being managed). Additionally, Ansible depends on several Python libraries, which must be installed and maintained on the control host. Some Ansible modules may also require specific libraries or packages to be installed on the managed nodes, adding to the complexity of managing dependencies.


Spot is an appealing choice for those seeking a lightweight, simple, and easy-to-use tool for deployment and configuration management, especially for smaller projects or when extensive features aren't necessary. Its single binary distribution, easy-to-comprehend structure, and minimal dependencies offer a low-maintenance solution. However, if a more comprehensive tool with a wide range of built-in modules, plugins, and integrations is needed, Ansible may be a better fit. While Ansible has advanced features and a robust ecosystem, its reliance on Python and additional libraries can sometimes be less convenient in certain environments or situations with specific constraints.

</details>

## Getting the latest development version

If you want to try the latest development version, you can install it directly from the master branch. There are two ways to do this:

- **Using go get**: `go install github.com/umputun/spot/cmd/spot@master` and `go install github.com/umputun/spot/cmd/secrets@master`. Note that this will install the latest development version of spot and secrets, which may not be stable or fully tested.
- **Using git**: `git clone github.com/umputun/spot` then `cd spot` and `make build`. This will install the latest development version of spot and secrets to `spot/.bin/spot` and `spot/.bin/sport-secrets`, respectively.

**pls note that you need to have go 1.16+ installed on your machine.**     


## Status

The project is currently in active development, and breaking changes may occur until the release of version 1.0. However, we strive to minimize disruptions and will only introduce breaking changes when there is a compelling reason to do so.

*Update: Version 1 has been released and is now considered stable. We do not anticipate any breaking changes for this version.*

## Contributing

Please feel free to open a discussion, submit issues, fork the repository, and send pull requests. See [CONTRIBUTING.md](https://github.com/umputun/spot/blob/master/CONTRIBUTING.md) for more information.

## License

This project is licensed under the MIT License. See the LICENSE file for more information.
