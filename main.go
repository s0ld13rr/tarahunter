package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/hirochachacha/go-smb2"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type HuntConfig struct {
	APTRules struct {
		FilePatterns          []string `yaml:"file_patterns"`
		CheckDoubleExtensions bool     `yaml:"check_double_extensions"`
		IOCHashes             []string `yaml:"ioc_hashes"`
	} `yaml:"apt_rules"`
	TargetedLocations []string `yaml:"targeted_locations"`
}

type ScanConfig struct {
	Username string
	Domain   string
	Password string
	NTHash   string
	Threads  int
	Timeout  time.Duration
	Hunt     *HuntConfig
	Download bool
	LootDir  string
}

var (
	matchCounter    int64
	hostsDone       int64
	accessibleCount int64
	cMain           = color.New(color.FgMagenta, color.Bold).SprintFunc()
	cGreen          = color.New(color.FgGreen, color.Bold).SprintFunc()
	cRed            = color.New(color.FgRed).SprintFunc()
)

func printLogo() {

	banner := `
    ████████╗ █████╗ ██████╗  █████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
    ╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
       ██║   ███████║██████╔╝███████║███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
       ██║   ██╔══██║██╔══██╗██╔══██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
       ██║   ██║  ██║██║  ██║██║  ██║██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
       ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝`

	subText := `
           > [ v1.0.0 "Chitin Shell" ]
           > [ Module: APT-Hunter ]
           > [ Author: s0ld13r & gemini ]
	`
	fmt.Println(cMain(banner))
	fmt.Printf("\x1b[36m%s\x1b[0m\n", subText)
}

func progressBar(pct, width int) string {
	filled := pct * width / 100
	if filled > width {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func getRemoteHash(s *smb2.Share, path string) (string, error) {
	f, err := s.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func huntInLocation(session *smb2.Session, fullPath string, config *ScanConfig, host string) {
	parts := strings.SplitN(fullPath, "\\", 2)
	if len(parts) < 2 {
		return
	}
	share, relPath := parts[0], parts[1]

	s, err := session.Mount(share)
	if err != nil {
		return
	}
	defer s.Umount()

	_ = fs.WalkDir(s.DirFS(relPath), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}

		filename := strings.ToLower(d.Name())
		matched := false
		reason := ""

		// 1. Поиск по паттернам имен
		for _, pattern := range config.Hunt.APTRules.FilePatterns {
			if m, _ := filepath.Match(strings.ToLower(pattern), filename); m {
				matched = true
				reason = "Pattern Match"
				break
			}
		}

		// 2. Двойные расширения (pdf.exe и т.д.)
		if !matched && config.Hunt.APTRules.CheckDoubleExtensions {
			extParts := strings.Split(filename, ".")
			if len(extParts) > 2 {
				badExts := map[string]bool{"exe": true, "ps1": true, "bat": true, "scr": true, "vbs": true}
				if badExts[extParts[len(extParts)-1]] {
					matched = true
					reason = "Double Extension"
				}
			}
		}

		// 3. Сверка SHA256 хешей (только для файлов < 15MB)
		if !matched && len(config.Hunt.APTRules.IOCHashes) > 0 {
			info, _ := d.Info()
			if info != nil && info.Size() < 15*1024*1024 {
				fHash, _ := getRemoteHash(s, filepath.Join(relPath, path))
				for _, ioc := range config.Hunt.APTRules.IOCHashes {
					if strings.EqualFold(fHash, ioc) {
						matched = true
						reason = "IOC Hash Match"
						break
					}
				}
			}
		}

		if matched {
			atomic.AddInt64(&matchCounter, 1)
			fmt.Printf("\r\033[K%s %s -> %s\\%s (%s)\n", cGreen("[!] FOUND:"), host, share, filepath.Join(relPath, path), reason)
			if config.Download {
				saveFile(s, filepath.Join(relPath, path), host, d.Name(), config.LootDir)
			}
		}
		return nil
	})
}

func saveFile(s *smb2.Share, remotePath, host, name, lootDir string) {
	_ = os.MkdirAll(filepath.Join(lootDir, host), 0755)
	src, err := s.Open(remotePath)
	if err != nil {
		return
	}
	defer src.Close()
	dst, _ := os.Create(filepath.Join(lootDir, host, name))
	if dst != nil {
		defer dst.Close()
		_, _ = io.Copy(dst, src)
	}
}

func scanHost(host string, config *ScanConfig, total int) {
	defer func() {
		current := atomic.AddInt64(&hostsDone, 1)
		pct := float64(current) / float64(total) * 100
		bar := progressBar(int(pct), 20)
		fmt.Printf("\r\033[K[%s] %5.1f%% (%d/%d) | OK: %d | Hits: %d",
			bar, pct, current, total, atomic.LoadInt64(&accessibleCount), atomic.LoadInt64(&matchCounter))
	}()

	conn, err := net.DialTimeout("tcp", host+":445", config.Timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	var initiator smb2.Initiator
	if config.NTHash != "" {
		hash := config.NTHash
		if strings.Contains(hash, ":") {
			hash = strings.Split(hash, ":")[len(strings.Split(hash, ":"))-1]
		}
		hashBytes, _ := hex.DecodeString(hash)
		initiator = &smb2.NTLMInitiator{User: config.Username, Domain: config.Domain, Hash: hashBytes, Password: ""}
	} else {
		initiator = &smb2.NTLMInitiator{User: config.Username, Domain: config.Domain, Password: config.Password}
	}

	d := &smb2.Dialer{Initiator: initiator}
	session, err := d.Dial(conn)
	if err != nil {
		return
	}
	defer session.Logoff()

	atomic.AddInt64(&accessibleCount, 1)

	for _, loc := range config.Hunt.TargetedLocations {
		// Поддержка Wildcard для пользователей
		if strings.Contains(loc, "\\*\\") {
			baseParts := strings.SplitN(loc, "\\*\\", 2)
			shareBase := strings.SplitN(baseParts[0], "\\", 2)
			if len(shareBase) < 2 {
				continue
			}
			s, err := session.Mount(shareBase[0])
			if err != nil {
				continue
			}
			entries, _ := s.ReadDir(shareBase[1])
			s.Umount()
			for _, entry := range entries {
				if entry.IsDir() {
					huntInLocation(session, filepath.Join(baseParts[0], entry.Name(), baseParts[1]), config, host)
				}
			}
		} else {
			huntInLocation(session, loc, config, host)
		}
	}
}

func main() {
	var config ScanConfig
	var target, huntFile string

	printLogo()

	rootCmd := &cobra.Command{
		Use: "tarahunter",
		Run: func(cmd *cobra.Command, args []string) {
			y, err := os.ReadFile(huntFile)
			if err != nil {
				fmt.Println(cRed("[-] Config not found!"))
				return
			}
			_ = yaml.Unmarshal(y, &config.Hunt)

			ips, _ := expandCIDR(target)
			total := len(ips)
			fmt.Printf("[*] Target: %s | User: %s | Threads: %d\n", target, config.Username, config.Threads)

			var wg sync.WaitGroup
			sem := make(chan struct{}, config.Threads)
			for _, ip := range ips {
				wg.Add(1)
				sem <- struct{}{}
				go func(i string) {
					defer wg.Done()
					defer func() { <-sem }()
					scanHost(i, &config, total)
				}(ip)
			}
			wg.Wait()
			fmt.Printf("\n\n%s Hunt finished. Matches: %d\n", cGreen("[+]"), atomic.LoadInt64(&matchCounter))
		},
	}

	rootCmd.Flags().StringVarP(&target, "target", "t", "", "CIDR Target (192.168.1.0/24)")
	rootCmd.Flags().StringVarP(&config.Username, "user", "u", "", "Username")
	rootCmd.Flags().StringVarP(&config.Domain, "domain", "d", ".", "Domain")
	rootCmd.Flags().StringVarP(&config.NTHash, "hash", "H", "", "NT Hash for PtH")
	rootCmd.Flags().StringVarP(&config.Password, "pass", "p", "", "Password")
	rootCmd.Flags().StringVarP(&huntFile, "config", "c", "hunt.yaml", "Path to YAML config")
	rootCmd.Flags().IntVar(&config.Threads, "threads", 40, "Number of threads")
	rootCmd.Flags().DurationVar(&config.Timeout, "timeout", 2*time.Second, "SMB Timeout")
	rootCmd.Flags().BoolVar(&config.Download, "download", false, "Download hits to loot")
	rootCmd.Flags().StringVar(&config.LootDir, "loot", "./loot", "Loot directory")

	rootCmd.MarkFlagRequired("target")
	rootCmd.MarkFlagRequired("user")
	rootCmd.Execute()
}

func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return []string{cidr}, nil
	}
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) < 2 {
		return ips, nil
	}
	return ips[1 : len(ips)-1], nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
