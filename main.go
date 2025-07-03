package main
import (
		"fmt"
		"os"
		"net"
		"bufio"
		"golang.org/x/crypto/ssh"
		"strconv"
		"strings"
		"time"
		"log"
		"io"
)

func stringPrompt(label string) string {
    var s string
    r := bufio.NewReader(os.Stdin)
    for {
        fmt.Fprint(os.Stderr, label+" ")
        s, _ = r.ReadString('\n')
        if s != "" {
            break
        }
    }
    return strings.TrimSpace(s)
}

func intPrompt(label string) int {
	var s string
	var i int
	var err error
	r := bufio.NewReader(os.Stdin)

	for {
		fmt.Fprint(os.Stderr, label+" ")
		s, _ = r.ReadString('\n')
		s = strings.TrimSpace(s)

		if s == "" {
			continue
		}

		i, err = strconv.Atoi(s)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Invalid input. Please enter a whole number.")
			continue
		}
		break
	}
	return i
}

func executeSSHCommand(ip, user, password, command string) error {
	
	//SSH into target
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(""), //Dummy password
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
		BannerCallback: func(message string) error {
			fmt.Printf("SSH Server Banner:\n%s\n", message)
			return nil
		},
	}

	// establish SSH connection
	addr := net.JoinHostPort(ip, "22")
	sshClient, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		log.Fatalf("Failed to establish SSH connection: %v", err)
	}
	defer sshClient.Close()

	fmt.Println("\nSuccessfully established SSH connection!")

	// Create session
	session, err := sshClient.NewSession()
	if err != nil {
		log.Fatalf("Failed to create SSH session: %v", err)
	}
	defer session.Close()

	// pseudo-terminal
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     
		ssh.TTY_OP_ISPEED: 14400, // input speed 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed 14.4kbaud
	}
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		log.Fatalf("Failed to request pseudo-terminal: %v", err)
	}

	// Get pipes
	stdin, err := session.StdinPipe()
	if err != nil {
		log.Fatalf("Failed to get stdin pipe: %v", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		log.Fatalf("Failed to get stdout pipe: %v", err)
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		log.Fatalf("Failed to get stderr pipe: %v", err)
	}

	// Start shell session
	if err := session.Shell(); err != nil {
		log.Fatalf("Failed to start shell: %v", err)
	}

	// handle login
	passwordSent := false
	loginComplete := make(chan bool, 1)
	
	go func() {
		scanner := bufio.NewScanner(io.MultiReader(stdout, stderr))
		loggedIn := false
		
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Printf("Server: %s\n", line)
			
			//Looks for password prompt
			if strings.Contains(strings.ToLower(line), "password") && strings.Contains(line, ":") && !passwordSent && !strings.Contains(line, "timed out") {
				_, err := stdin.Write([]byte(password + "\n"))
				if err != nil {
					log.Printf("password failed: %v", err)
				} 
			} else if strings.Contains(line, "rkscli:") && !loggedIn {
				// CLI prompt indicating successful login
				fmt.Println("rkscli prompt detected")
				loggedIn = true
				select {
				case loginComplete <- true:
				default:
				}
			} else if strings.Contains(line, "timed out") {
				fmt.Printf("Timed out\n")
			}
		}
		
		if err := scanner.Err(); err != nil {
			log.Printf("Scanner error: %v", err)
		}
	}()

	// wait then send username
	time.Sleep(1 * time.Second)
	
	_, err = stdin.Write([]byte(user + "\n"))
	if err != nil {
		log.Fatalf("username failed: %v", err)
	}
	//wait then send password
	time.Sleep(2 * time.Second)
	fmt.Printf("Sending password: %s\n", password)
	_, err = stdin.Write([]byte(password + "\n"))
	if err != nil {
		log.Fatalf("password failed: %v", err)
	}

	// Wait for rkscli
	fmt.Printf("Waiting for login to complete...\n")
	select {
	case <-loginComplete:
		fmt.Println("Login completed successfully!")
		// wait before running command
		time.Sleep(2 * time.Second)

		// send command
		fmt.Printf("running command: %s\n", command)
		_, err = stdin.Write([]byte(command + "\n"))
		if err != nil {
			log.Fatalf("Failed to run command: %v", err)
		}
	case <-time.After(30 * time.Second):
		fmt.Println("Login timeout - unable to detect rkscli prompt. Exiting.")
		return err
	}

	// wait for output
	fmt.Println("Waiting for output")
	time.Sleep(3 * time.Second)

	// exit all nice like
	fmt.Println("Exiting politely")
	stdin.Write([]byte("exit\n"))
	stdin.Close()

	// session error
	if err := session.Wait(); err != nil {
		log.Printf("Session error: %v", err)
	}

	fmt.Println("Finish")
	return nil
}

func main() {
	//get info
	ip := stringPrompt("Enter the IP address:")
	user := stringPrompt("Enter the username:")
	password := stringPrompt("Enter the password:")
	command := stringPrompt("Enter the command to run:")
	hours := intPrompt("Enter the wait time in hours:")
	minutes := intPrompt("Enter the wait time in minutes:")
	seconds := intPrompt("Enter the wait time in seconds:")
	
	//convert time 
	waitTime := time.Duration(hours)*time.Hour + time.Duration(minutes)*time.Minute + time.Duration(seconds)*time.Second
	
	//print info
	fmt.Printf("IP: %s, User: %s, Password: %s, Command: %s\n", ip, user, password, command)
	fmt.Printf("Running Command In: %v\n", waitTime)
	fmt.Printf("Press Ctrl + C to cancel\n")
	
	//tcp test
	fmt.Printf("Checking IP %s:22...\n", ip)
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "22"), 5*time.Second)
	if err != nil {
		log.Fatalf("IP failed: %v", err)
	}
	defer conn.Close()
	fmt.Println("IP good")
	
	//Sleep for waitTime
	time.Sleep(waitTime)
	
	// Execute SSH command
	err = executeSSHCommand(ip, user, password, command)
	if err != nil {
		log.Fatalf("SSH command failed: %v", err)
	}
}
