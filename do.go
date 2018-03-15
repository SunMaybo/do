package main

import (
	"os"
	"gopkg.in/yaml.v2"
	"path/filepath"
	"strings"
	"log"
	"golang.org/x/crypto/ssh"
	"net"
	"os/exec"
	"fmt"
	"io/ioutil"
	"github.com/pkg/sftp"
	"path"
	"strconv"
	"time"
)

var data = `server:
             api-authorize:
                       name: api-authorize
                       env: uat
                       port: 9004
                       user: java
                       password: javaoffice2015
                       exec: -Xmx512m
                       ssh_port: 22
                       hosts:
                           - 127.0.0.1
            work_dir: dotconnect_service 
`
var startShell = "#!/bin/bash\n" +
	"echo -e \"Starting the $1 ............\\c\"\n" +
	"nohup java $4 -jar /home/java/dotconnect_service/$2/$3/$1.jar –spring.profiles.active=$2 >&1 &\n" +
	"echo \"OK!\"\n" +
	"PIDS=`ps -f | grep java | grep \"$1.jar\" |awk '{print $2}'`\n" +
	"echo \"PID: $PIDS\n\""
var stopShell = "#!/bin/bash\n" +
	"echo -e \"Stoping the $1 ............\\c\"\n" +
	"kill -15 `/usr/sbin/lsof -t -i:$2`\n" +
	"kill -2 `/usr/sbin/lsof -t -i:$2`\n" +
	"kill -1 `/usr/sbin/lsof -t -i:$2`\n" +
	"echo \"OK!\"\n" +
	"PIDS=`ps -f | grep java | grep \"$1.jar\" |awk '{print $2}'`\n" +
	"echo \"PID: $PIDS\"\n"

type CI struct {
	Server  map[string]Task `yaml:"server"`
	WorkDir string          `yaml:"work_dir"`
	Version string          `yaml:"version"`
}

type Task struct {
	Name     string   `yaml:"name"`
	Env      string   `yaml:"env""`
	Hosts    []string `yaml:"hosts"`
	Port     int      `yaml:"port"`
	Exec     string   `yaml:"exec"`
	Password string   `yaml:"password"`
	User     string   `yaml:"user"`
	SshPort  int      `yaml:"ssh_port"`
}

func main() {

	ci, bootType, module := ArgsParser()
	if ci == nil {
		log.Fatal("load ci.yml error")
		return
	}
	if bootType == "start" {
		if module == "" {
			count := 0
			var messages chan string = make(chan string, 100)
			for module := range ci.Server {
				task := ci.Server[module]
				for i := 0; i < len(task.Hosts); i++ {
					count++
					go func(host string, port int, password string, user string, workDir string, module string, env string, version string, exec string) {
						ProjectStart(host, port, password, user, workDir, module, env, version, exec)
						messages <- "-----" + host + ":" + strconv.Itoa(port) + "-------" + module + "-----------"
					}(task.Hosts[i], task.SshPort, task.Password, task.User, ci.WorkDir, module, task.Env, ci.Version, task.Exec)
				}
			}
			for j := 0; j < count; j++ {
				fmt.Println(<-messages)
			}

		} else {
			count := 0
			messages := make(chan string, 100)
			task := ci.Server[module]
			for i := 0; i < len(task.Hosts); i++ {
				count++
				go func(host string, port int, password string, user string, workDir string, module string, env string, version string, exec string) {
					ProjectStart(host, port, password, user, workDir, module, env, version, exec)
					messages <- "-----" + host + ":" + strconv.Itoa(port) + "-------" + module + "-----------"
				}(task.Hosts[i], task.SshPort, task.Password, task.User, ci.WorkDir, module, task.Env, ci.Version, task.Exec)
			}
			for j := 0; j < count; j++ {
				fmt.Println(<-messages)
			}

		}
		return
	}
	if bootType == "stop" {
		if module == "" {
			count := 0
			messages := make(chan string, 100)
			for module := range ci.Server {
				task := ci.Server[module]
				for i := 0; i < len(task.Hosts); i++ {
					count++
					go func(workDir string, host string, port int, password string, user string, projectPort int, module string) {
						ProjectStop(workDir, host, port, password, user, projectPort, module)
						messages <- "-----" + host + ":" + strconv.Itoa(port) + "-------" + module + "-----------"
					}(ci.WorkDir, task.Hosts[i], task.SshPort, task.Password, task.User, task.Port, module)
				}
			}
			for j := 0; j < count; j++ {
				fmt.Println(<-messages)
			}
		} else {
			count := 0
			messages := make(chan string, 100)
			task := ci.Server[module]
			for i := 0; i < len(task.Hosts); i++ {
				count++
				go func(workDir string, host string, port int, password string, user string, projectPort int, module string) {
					ProjectStop(workDir, host, port, password, user, projectPort, module)
					messages <- "-----" + host + ":" + strconv.Itoa(port) + "-------" + module + "-----------"
				}(ci.WorkDir, task.Hosts[i], task.SshPort, task.Password, task.User, task.Port, module)
			}
			for j := 0; j < count; j++ {
				fmt.Println(<-messages)
			}
		}
		return
	}
	if bootType == "restart" {
		if module == "" {
			count := 0
			messages := make(chan string, 100)
			for module := range ci.Server {
				task := ci.Server[module]
				for i := 0; i < len(task.Hosts); i++ {
					count++
					go func(host string, port int, password string, user string, workDir string, module string, env string, version string, exec string, projectPort int) {
						ProjectRestart(host, port, password, user, workDir, module, env, version, exec, projectPort)
						messages <- "-----" + host + ":" + strconv.Itoa(port) + "-------" + module + "-----------"
					}(task.Hosts[i], task.SshPort, task.Password, task.User, ci.WorkDir, module, task.Env, ci.Version, task.Exec, task.Port)
				}
			}
			for j := 0; j < count; j++ {
				fmt.Println(<-messages)
			}
		} else {
			count := 0
			messages := make(chan string, 100)
			task := ci.Server[module]
			for i := 0; i < len(task.Hosts); i++ {
				count++
				go func(host string, port int, password string, user string, workDir string, module string, env string, version string, exec string, projectPort int) {
					ProjectRestart(host, port, password, user, workDir, module, env, version, exec, projectPort)
					messages <- "-----" + host + ":" + strconv.Itoa(port) + "-------" + module + "-----------"
				}(task.Hosts[i], task.SshPort, task.Password, task.User, ci.WorkDir, module, task.Env, ci.Version, task.Exec, task.Port)
			}
			for j := 0; j < count; j++ {
				fmt.Println(<-messages)
			}
		}
		return
	}
	if bootType == "push" {
		if module == "" {
			count := 0
			messages := make(chan string, 100)
			for module := range ci.Server {
				task := ci.Server[module]
				for i := 0; i < len(task.Hosts); i++ {
					count++
					go func(workDir string, host string, port int, password string, user string, fileName string, env string, version string, module string) {
						ProjectPush(workDir, host, port, password, user, fileName, env, version, module)
						messages <- host + ":" + strconv.Itoa(port) + "-" + module
					}(ci.WorkDir, task.Hosts[i], task.SshPort, task.Password, task.User, FindJar("", module), task.Env, ci.Version, module)
				}
			}
			for j := 0; j < count; j++ {
				fmt.Println(<-messages)
			}
		} else {
			count := 0
			task := ci.Server[module]
			messages := make(chan string, 100)
			for i := 0; i < len(task.Hosts); i++ {
				count++
				go func(workDir string, host string, port int, password string, user string, fileName string, env string, version string, module string) {
					ProjectPush(workDir, host, port, password, user, fileName, env, version, module)
					messages <- host + ":" + strconv.Itoa(port) + "-" + module
				}(ci.WorkDir, task.Hosts[i], task.SshPort, task.Password, task.User, FindJar("", module), task.Env, ci.Version, module)
			}
			for j := 0; j < count; j++ {
				fmt.Println(<-messages)
			}
		}
		return
	}
	if bootType == "pull" {
		log.Println("暂时未开放")
		return
	}
}
func ArgsParser() (*CI, string, string) {
	f := ""
	v := ""
	d := ""
	u := ""
	h := ""
	pwd := ""
	e := ""
	m := ""
	exec := ""
	P := 0
	p := 0
	help := false
	all := false
	module := ""
	args := os.Args //获取用户输入的所有参数
	if args == nil || len(args) < 2 {
		log.Fatal("params invalid")
	}
	if len(args) < 3 && args[1] == "--h" {
		fmt.Println(ArgsHelp())
		return nil, "", ""
	}
	if strings.Index(args[1], "-") == 0 {
		log.Fatal("params invalid")
		return nil, "", ""
	}
	bootType := args[1]
	for i := 2; i < len(args); i++ {
		if "-f" == args[i] {
			if i+1 >= len(args) {
				log.Fatalf("params -f invalid")
				break
			}
			f = args[i+1]
		}
		if "-v" == args[i] {
			if i+1 >= len(args) {
				log.Fatalf("params -v invalid")
				break
			}
			v = args[i+1]
		}
		if "-d" == args[i] {
			if i+1 >= len(args) {
				log.Fatalf("params -d invalid")
				break
			}
			d = args[i+1]
		}
		if "-u" == args[i] {
			if i+1 >= len(args) {
				log.Fatalf("params -u invalid")
				break
			}
			u = args[i+1]
		}
		if "-h" == args[i] {
			if i+1 >= len(args) {
				log.Fatalf("params -h invalid")
				break
			}
			h = args[i+1]
		}
		if "-pwd" == args[i] {
			if i+1 >= len(args) {
				log.Fatalf("params -pwd invalid")
				break
			}
			pwd = args[i+1]
		}
		if "-e" == args[i] {
			if i+1 >= len(args) {
				log.Fatalf("params -e invalid")
				break
			}
			e = args[i+1]
		}
		if "-m" == args[i] {
			if i+1 >= len(args) {
				log.Fatalf("params -m invalid")
				break
			}
			m = args[i+1]
		}
		if "-p" == args[i] {
			if i+1 >= len(args) {
				log.Fatalf("params -p invalid")
				break
			}
			p, _ = strconv.Atoi(args[i+1])
		}
		if "-P" == args[i] {
			if i+1 >= len(args) {
				log.Fatalf("params -P invalid")
				break
			}
			P, _ = strconv.Atoi(args[i+1])
		}
		if "-exec" == args[i] {
			if i+1 >= len(args) {
				log.Fatalf("params -exec invalid")
				break
			}
			exec = args[i+1]
		}
		if "--h" == args[i] {
			help = true
		}
		if "--all" == args[i] {
			all = true
		}
	}
	if help {
		fmt.Print(ArgsHelp())
		return nil, "", ""
	}
	ci, error := LoadYml(f)
	Check(error, "ci.yml parse error")
	if d != "" {
		ci.WorkDir = d
	}
	if v != "" {
		ci.Version = v
	}
	if all {
		return &ci, bootType, ""
	} else if m == "" && !all {
		log.Fatal("params -all invalid")
		os.Exit(0)
		return &ci, "", ""
	} else {
		module = m
		server, ok := ci.Server[module]
		if !ok {
			ci.Server[module] = Task{}
			server = ci.Server[module]
		}
		if u != "" {
			server.User = u
		}
		if h != "" {
			server.Hosts = []string{h}
		}
		if P > 0 {
			server.SshPort = P
		}
		if p > 0 {
			server.Port = p
		}
		if pwd != "" {
			server.Password = pwd
		}
		if e != "" {
			server.Env = e
		}
		if m != "" {
			server.Name = module
		}
		if e != "" {
			server.Exec = exec
		}
		ci.Server[module] = server
		return &ci, bootType, module
	}

}
func ArgsHelp() string {
	return "" +
		"----------------------------------------------------------------------------------\n" +
		"----------------      CI     RUN    SPRING     BOOT            -------------------\n" +
		"----------------      CI     RUN    SPRING     BOOT            -------------------\n" +
		"----------------      CI     RUN    SPRING     BOOT            -------------------\n" +
		"----------------------------------------------------------------------------------\n" +

		"你可以使用[stop][start][restart][push][pull]帮助项目的发布\n\n" +

		"-f             指定加载的ci.yml用于集群的管理配置\n\n" +

		"-v             指定项目的版本在ci.yml中对应version属性\n\n" +

		"-d             指定部署到的工作目录\n\n" +

		"-u             指定服务器的用户名\n\n" +

		"-h             指定服务器的IP地址\n\n" +

		"-P             指定服务器的端口号为ssh端口号\n\n" +

		"-p             指定项目的端口号\n\n" +

		"-pwd           指定服务器的密码\n\n" +

		"-exec          指定执行启动计划所需要的命令\n\n" +

		"-e             指定部署项目的环境\n\n" +

		"-m             指定部署模块的名字\n\n" +

		"--all          指定所有的模块，来自ci.yml的配置\n\n" +

		"--h            显示帮助信息\n\n"
}
func ProjectStop(workDir string, host string, port int, password string, user string, projectPort int, module string) {
	client := SshShellClient(host+":"+strconv.Itoa(port), user, password)
	Kill(workDir, user, module, projectPort, client)
	client.Close()
	log.Println("-------" + host + "------" + module + "-----------" + "-----------------------")

}
func ProjectStart(host string, port int, password string, user string, workDir string, module string, env string, version string, exec string) {
	client := SshShellClient(host+":"+strconv.Itoa(port), user, password)
	Start(user, workDir, module, env, version, exec, client)
	client.Close()
	log.Println("-------" + host + "------" + module + "-----------" + "---------" + env + "--------------")
}
func ProjectRestart(host string, port int, password string, user string, workDir string, module string, env string, version string, exec string, projectPort int) {
	client := SshShellClient(host+":"+strconv.Itoa(port), user, password)
	Kill(workDir, user, module, projectPort, client)
	time.Sleep(2 * time.Second)
	Start(user, workDir, module, env, version, exec, client)
	client.Close()
	log.Println("-------" + host + "------" + module + "-----------" + "---------" + env + "--------------")
}
func Start(user string, workDir string, module string, env string, version string, exec string, sshClient *ssh.Client) {
	session := SshShellSession(sshClient)
	//var cmdStr = "nohup java ?1 -jar /home/?2/dotconnect_service/?3/?4/?5.jar --spring.profiles.active=?6 >/dev/null 2>&1 &\n"
	var cmdStr = "sh /home/?2/?6/start.sh ?5 ?3 ?4 ?1"
	cmdStr = strings.Replace(cmdStr, "?1", exec, 1)
	cmdStr = strings.Replace(cmdStr, "?2", user, 1)
	cmdStr = strings.Replace(cmdStr, "?3", env, 1)
	cmdStr = strings.Replace(cmdStr, "?4", version, 1)
	cmdStr = strings.Replace(cmdStr, "?5", module, 1)
	cmdStr = strings.Replace(cmdStr, "?6", workDir, 1)
	sshExecute(cmdStr, session)
	session.Close()
}
func Kill(workDir string, user string, module string, projectPort int, sshClient *ssh.Client) {
	//kill项目
	session := SshShellSession(sshClient)
	//kill
	var kill = "sh /home/?1/?4/stop.sh ?2 ?3"
	kill = strings.Replace(kill, "?1", user, 1)
	kill = strings.Replace(kill, "?2", module, 1)
	kill = strings.Replace(kill, "?3", strconv.Itoa(projectPort), 1)
	kill = strings.Replace(kill, "?4", workDir, 1)
	sshExecute(kill, session)
	session.Close()
}
func ProjectPush(workDir string, host string, port int, password string, user string, fileName string, env string, version string, module string) {
	var ipAddress = host + ":" + strconv.Itoa(port)
	sshClient := SshShellClient(ipAddress, user, password)
	session := SshShellSession(sshClient)
	var remoteDir = "/home/" + user + "/" + workDir + "/" + env + "/" + version
	var cmd = "mkdir -p " + remoteDir
	sshExecute(cmd, session)
	session.Close()
	//初始化加载目录
	LoadShell(workDir, host, port, password, user)
	//上传文件
	sftpClient, error := SshSessionFtp(sshClient)
	Check(error, "create sftp error")
	UploadFile(sftpClient, fileName, remoteDir+"/"+module+".jar")
}
func LoadShell(workDir string, host string, port int, password string, user string) {
	//初始化加载目录
	var ipAddress = host + ":" + strconv.Itoa(port)
	sshClient := SshShellClient(ipAddress, user, password)
	sftpClient, error := SshSessionFtp(sshClient)
	Check(error, "create sftp error")
	UploadString(sftpClient, startShell, "/home/"+user+"/"+workDir+"/start.sh")
	UploadString(sftpClient, stopShell, "/home/"+user+"/"+workDir+"/stop.sh")
	sftpClient.Close()
	session := SshShellSession(sshClient)
	session.Run("chmod 777" + " /home/" + user + "/" + workDir + "/*.sh")
	session.Close()
	sshClient.Close()

}
func LoadYml(fileName string) (CI, error) {
	if fileName == "" {
		fileName = GetCurrentDirectory() + "/ci.yml";
	}
	ci := CI{}
	log.Println(fileName)
	if strings.Index(fileName, ".") == 0 {
		fileName = GetCurrentDirectory() + fileName[1:len(fileName)]
	}
	//把yaml形式的字符串解析成struct类型
	err := yaml.Unmarshal(ReadFile(fileName), &ci)
	//修改struct里面的记录

	return ci, err
}
func GetCurrentDirectory() string {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}
	return strings.Replace(dir, "\\", "/", -1)
}
func Check(err error, msg string) {
	if err != nil {
		log.Fatalf("%s error: %v", msg, err)
	}
}
func SshShellClient(ipAddress string, user string, password string) *ssh.Client {
	// An SSH client is represented with a ClientConn. Currently only
	// the "password" authentication method is supported.
	//
	// To authenticate with the remote server you must pass at least one
	// implementation of AuthMethod via the Auth field in ClientConfig.

	client, err := ssh.Dial("tcp", ipAddress, &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		//需要验证服务端，不做验证返回nil就可以，点击HostKeyCallback看源码就知道了
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	})
	Check(err, "dial")
	return client
}
func SshShellSession(client *ssh.Client) *ssh.Session {
	session, err := client.NewSession()
	Check(err, "new session")

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	err = session.RequestPty("xterm", 25, 100, modes)
	Check(err, "request pty")

	return session
}
func shell(session *ssh.Session) {
	err := session.Shell()
	Check(err, "start shell")
	err = session.Wait()
	Check(err, "return")
}
func sshExecute(cmdStr string, session *ssh.Session) {
	err := session.Run(cmdStr)
	if err != nil {
		log.Print("execute error")
	}
	//check(err, "start shell")
	/*err = session.Wait()
	check(err, "return")*/
}
func SshSessionFtp(client *ssh.Client) (*sftp.Client, error) {

	var sftpClient *sftp.Client
	var err error
	// create sftp client
	if sftpClient, err = sftp.NewClient(client); err != nil {
		return nil, err
	}

	return sftpClient, nil

}
func UploadFile(client *sftp.Client, localFilePath string, remoteFileName string) {

	// 用来测试的本地文件路径 和 远程机器上的文件夹
	//localFilePath = "/Users/maybo/demo.txt"
	//	var remoteDir = "./"
	srcFile, err := os.Open(localFilePath)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
	defer srcFile.Close()
	dstFile, err := client.Create(remoteFileName)
	if err != nil {
		log.Fatal(err)
	}
	defer dstFile.Close()
	fileInfo, error := srcFile.Stat()
	if error != nil {
		Check(error, "open file error")
	}
	var size int64 = fileInfo.Size() / (1024 * 1024)
	var length = fileInfo.Size()
	var count int64 = 0
	var start = time.Now().Unix()
	var bef int64 = 0
	var buf []byte
	for {
		if length <= 1024*1024 {
			buf = make([]byte, length)
		} else {
			buf = make([]byte, 1024*1024)
			length -= 1024 * 1024
		}

		n, _ := srcFile.Read(buf)
		if n == 0 {
			break
		}
		dstFile.Write(buf)
		end := time.Now().Unix()
		if end-start >= 2 {
			Progress(remoteFileName, float32(count-bef)/float32(end-start)*float32(1024), float32(count)/float32(size))
			bef = count
			start = time.Now().Unix()
		}
		count++
	}
	fmt.Println("\r\n")
	fmt.Println("copy file to remote server finished!")
	
}
func UploadString(client *sftp.Client, content string, fileName string) {

	// 用来测试的本地文件路径 和 远程机器上的文件夹
	//	var localFilePath = "/Users/maybo/zookeeper-3.3.6.tar.gz"
	//	var remoteDir = "./"
	dstFile, err := client.Create(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer dstFile.Close()

	dstFile.Write([]byte(content))

	fmt.Println("copy file to remote server finished!")
}
func DownloadFile(client *sftp.Client) {

	defer client.Close()

	// 用来测试的远程文件路径 和 本地文件夹
	var remoteFilePath = "/home/java/nohup.out"
	var localDir = "/Users/maybo/"

	srcFile, err := client.Open(remoteFilePath)
	if err != nil {
		log.Fatal(err)
	}
	defer srcFile.Close()

	var localFileName = path.Base(remoteFilePath)
	dstFile, err := os.Create(path.Join(localDir, localFileName))
	if err != nil {
		log.Fatal(err)
	}
	defer dstFile.Close()

	if _, err = srcFile.WriteTo(dstFile); err != nil {
		log.Fatal(err)
	}

	fmt.Println("copy file from remote server finished!")

}
func Execute(cmdStr string) string {
	cmd := exec.Command("sh", "-c", cmdStr)
	out, err := cmd.Output()
	if err != nil {
		fmt.Errorf(err.Error())
		os.Exit(0);
		return ""
	} else {
		return string(out)
	}
}
func FindJar(workSpace string, module string) string {
	if workSpace == "" {
		workSpace = GetCurrentDirectory()
	}
	var fileName = ""
	error := filepath.Walk(workSpace, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() && strings.Index(info.Name(), module) == 0 && path[len(path)-3:len(path)] == "jar" {
			fileName = path
			return nil
		} else {
			return err
		}
	});
	if error != nil {
		Check(error, "select jar expection")
	}
	return fileName

}
func ReadFile(path string) []byte {
	configFile, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatalf("yamlFile.Get err %v ", err)
	}
	return configFile
}
func Progress(module string, speed float32, rate float32) {
	str := "[     " + module + "      ] " + "  " + strconv.FormatFloat(float64(speed), 'f', -1, 32) + "kb/s" + "  " + strconv.Itoa(int(rate*100)) + "%"
	fmt.Printf("\r%s", str)
}
