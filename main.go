// v2go - High-Performance V2Ray Config Aggregator (Go Edition)
// Copyright (C) 2025  Danialsamadi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

const (
	timeout         = 20 * time.Second
	maxWorkers      = 10
	maxLinesPerFile = 500
)

var fixedText = `#profile-title: base64:8J+GkyBHaXRodWIgfCBEYW5pYWwgU2FtYWRpIPCfkI0=
#profile-update-interval: 1
#support-url: https://github.com/Danialsamadi/v2go
#profile-web-page-url: https://github.com/Danialsamadi/v2go
`

var protocols = []string{"vmess", "vless", "trojan", "ss", "ssr", "hy2", "tuic", "warp://"}

var links = []string{
	"https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/sub.txt",
	"https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
	"https://raw.githubusercontent.com/ts-sf/fly/main/v2",
	"https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mci/sub_1.txt",
	"https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mci/sub_2.txt",
	"https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mci/sub_3.txt",
	"https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/app/sub.txt",
	"https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_1.txt",
	"https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_2.txt",
	"https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_3.txt",
	"https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_4.txt",
	"https://raw.githubusercontent.com/yebekhe/vpn-fail/refs/heads/main/sub-link",
}

var dirLinks = []string{
	"https://v2.alicivil.workers.dev",
	"https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/mixed",
	"https://raw.githubusercontent.com/itsyebekhe/PSG/main/lite/subscriptions/xray/normal/mix",
	"https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",
	"https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/mix/sub.html",
	"https://raw.githubusercontent.com/Rayan-Config/C-Sub/refs/heads/main/configs/proxy.txt",
	"https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
	"https://raw.githubusercontent.com/Everyday-VPN/Everyday-VPN/main/subscription/main.txt",
	"https://raw.githubusercontent.com/MahsaNetConfigTopic/config/refs/heads/main/xray_final.txt",
	"https://github.com/Epodonios/v2ray-configs/raw/main/All_Configs_Sub.txt",
	"https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
	"https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vmess.txt",
	"https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/all_extracted_configs.txt",
	"https://raw.githubusercontent.com/miladtahanian/V2RayScrapeByCountry/refs/heads/main/output_configs/Vless.txt",
	"https://raw.githubusercontent.com/miladtahanian/V2RayScrapeByCountry/refs/heads/main/output_configs/Vmess.txt",
	"https://raw.githubusercontent.com/miladtahanian/V2ray-Config/main/All_Configs_Sub.txt",
	"https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/all_configs.txt",
	"https://raw.githubusercontent.com/Kolandone/v2raycollector/refs/heads/main/config.txt",
	"https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",
	"https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vmess.txt",
	"https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/trojan.txt",
	"https://raw.githubusercontent.com/Surfboardv2ray/TGParse/refs/heads/main/configtg.txt",
	"https://raw.githubusercontent.com/shabane/kamaji/refs/heads/master/hub/merged.txt",
	"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
	"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
	"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS+All_RUS.txt",
	"https://raw.githubusercontent.com/frank-vpl/servers/refs/heads/main/irbox",
}

type Result struct {
	URL        string
	Content    string
	IsBase64   bool
	StatusCode int
	Error      error
}

var (
	geoDB    *geoip2.Reader
	geoCache sync.Map // cache for host -> country code
)

func main() {
	start := time.Now()
	fmt.Println("Starting V2Ray config aggregator...")

	// Ensure directories exist
	base64Folder, err := ensureDirectoriesExist()
	if err != nil {
		fmt.Printf("Error creating directories: %v\n", err)
		return
	}

	// Create HTTP client with connection pooling
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	// Download and open GeoIP database
	if err := downloadGeoIPDB(); err != nil {
		fmt.Printf("Warning: Could not download GeoIP database: %v\n", err)
	} else {
		db, err := geoip2.Open("GeoLite2-Country.mmdb")
		if err == nil {
			geoDB = db
			defer geoDB.Close()
		} else {
			fmt.Printf("Warning: Could not open GeoIP database: %v\n", err)
		}
	}

	// Fetch all URLs concurrently
	fmt.Println("Fetching configurations from sources...")
	allConfigs, failedLinks := fetchAllConfigs(client, links, dirLinks)

	// Filter for protocols
	fmt.Println("Filtering configurations and removing duplicates...")
	originalCount := len(allConfigs)
	filteredConfigs, configsByCountry := filterForProtocols(allConfigs, protocols)

	fmt.Printf("Found %d unique valid configurations\n", len(filteredConfigs))
	fmt.Printf("Removed %d duplicates\n", originalCount-len(filteredConfigs))

	// Clean existing files
	cleanExistingFiles(base64Folder)

	// Write main config file (in current directory)
	mainOutputFile := "AllConfigsSub.txt"
	err = writeMainConfigFile(mainOutputFile, filteredConfigs)
	if err != nil {
		fmt.Printf("Error writing main config file: %v\n", err)
		return
	}

	// Split into smaller files
	fmt.Println("Splitting into smaller files...")
	err = splitIntoFiles(base64Folder, filteredConfigs)
	if err != nil {
		fmt.Printf("Error splitting files: %v\n", err)
		return
	}

	// Calculate protocol statistics
	stats := calculateStats(filteredConfigs)

	// Write country-specific files
	fmt.Println("Writing country-specific files...")
	writeCountryFiles(configsByCountry)

	// Write summary to UPDATE_SUMMARY.md
	processingTime := time.Since(start).Seconds()
	writeUpdateSummary(len(filteredConfigs), stats, processingTime, originalCount, failedLinks)

	// Now sort configurations by protocol
	sortConfigs()
}

func ensureDirectoriesExist() (string, error) {
	// Create Base64 directory
	base64Folder := "Base64"
	if err := os.MkdirAll(base64Folder, 0755); err != nil {
		return "", err
	}

	// Create Splitted-By-Country directory
	if err := os.MkdirAll("Splitted-By-Country", 0755); err != nil {
		return "", err
	}

	return base64Folder, nil
}

func fetchAllConfigs(client *http.Client, base64Links, textLinks []string) ([]string, []string) {
	var wg sync.WaitGroup
	resultChan := make(chan Result, len(base64Links)+len(textLinks))
	var failedLinks []string

	// Worker pool for concurrent requests
	semaphore := make(chan struct{}, maxWorkers)

	// Fetch base64-encoded links
	for _, link := range base64Links {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			res := fetchAndDecodeBase64(client, url)
			resultChan <- res
		}(link)
	}

	// Fetch text links
	for _, link := range textLinks {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			res := fetchText(client, url)
			resultChan <- res
		}(link)
	}

	// Close channel when all goroutines are done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var allConfigs []string
	for result := range resultChan {
		if result.StatusCode != http.StatusOK || result.Error != nil {
			status := "Error"
			if result.StatusCode > 0 {
				status = fmt.Sprintf("HTTP %d", result.StatusCode)
			}
			failedLinks = append(failedLinks, fmt.Sprintf("%s (%s)", result.URL, status))
			continue
		}

		lines := strings.Split(strings.TrimSpace(result.Content), "\n")
		allConfigs = append(allConfigs, lines...)
	}

	return allConfigs, failedLinks
}

func fetchAndDecodeBase64(client *http.Client, url string) Result {
	res := Result{URL: url, IsBase64: true}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		res.Error = err
		return res
	}

	resp, err := client.Do(req)
	if err != nil {
		res.Error = err
		return res
	}
	defer resp.Body.Close()

	res.StatusCode = resp.StatusCode
	if resp.StatusCode != http.StatusOK {
		return res
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		res.Error = err
		return res
	}

	// Try to decode base64
	decoded, err := decodeBase64(body)
	if err != nil {
		res.Error = err
		return res
	}

	res.Content = decoded
	return res
}

func fetchText(client *http.Client, url string) Result {
	res := Result{URL: url, IsBase64: false}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		res.Error = err
		return res
	}

	resp, err := client.Do(req)
	if err != nil {
		res.Error = err
		return res
	}
	defer resp.Body.Close()

	res.StatusCode = resp.StatusCode
	if resp.StatusCode != http.StatusOK {
		return res
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		res.Error = err
		return res
	}

	res.Content = string(body)
	return res
}

func decodeBase64(encoded []byte) (string, error) {
	// Add padding if necessary
	encodedStr := string(encoded)
	if len(encodedStr)%4 != 0 {
		encodedStr += strings.Repeat("=", 4-len(encodedStr)%4)
	}

	decoded, err := base64.StdEncoding.DecodeString(encodedStr)
	if err != nil {
		return "", err
	}

	return string(decoded), nil
}

// sanitizeConfig fixes common issues in config strings from upstream sources.
func sanitizeConfig(config string) string {
	// Fix HTML entities: &amp; → &
	config = strings.ReplaceAll(config, "&amp;", "&")
	return config
}

// isValidConfig checks whether a config has parameters that would crash V2Ray clients.
// Returns false if the config should be skipped.
func isValidConfig(config string) bool {
	// Extract query string (between ? and #)
	qStart := strings.Index(config, "?")
	if qStart < 0 {
		return true // no query params, nothing to validate
	}
	qEnd := strings.Index(config[qStart:], "#")
	var query string
	if qEnd >= 0 {
		query = config[qStart+1 : qStart+qEnd]
	} else {
		query = config[qStart+1:]
	}

	// Parse query params and validate sni and path
	for _, param := range strings.Split(query, "&") {
		kv := strings.SplitN(param, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])

		if key == "sni" || key == "path" {
			// Reject if value contains non-ASCII chars (emojis, CJK, etc.) or raw brackets
			for _, r := range val {
				if r > 127 || r == '[' || r == ']' {
					return false
				}
			}
		}
	}
	return true
}

func filterForProtocols(data []string, protocols []string) ([]string, map[string][]string) {
	var filtered []string
	configsByCountry := make(map[string][]string)
	seen := make(map[string]bool)
	var mu sync.Mutex

	type configRes struct {
		line    string
		country string
		proto   string
	}

	// Use a worker pool for parallel country lookup and deduplication
	jobs := make(chan string, 100)
	results := make(chan configRes, 100)

	const numWorkers = 300
	var wg sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for line := range jobs {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}

				// Identify protocol
				var currentProtocol string
				for _, protocol := range protocols {
					prefix := protocol
					if !strings.HasSuffix(prefix, "://") && protocol != "warp://" {
						prefix += "://"
					}
					if strings.HasPrefix(line, prefix) {
						currentProtocol = protocol
						break
					}
				}

			if currentProtocol == "" {
				continue
			}

			// Validate config: reject configs with invalid SNI/path that crash clients
			if !isValidConfig(line) {
				continue
			}

			// Smart Deduplication: Parse core identity (Address + Port)
				identity := parseCoreIdentity(line, currentProtocol)

				mu.Lock()
				if seen[identity] {
					mu.Unlock()
					continue
				}
				seen[identity] = true
				mu.Unlock()

				// Life Guard: Port Checker (TCP Connectivity Test)
				host, port := getHostPort(line, currentProtocol)
				if !checkPort(host, port) {
					continue
				}

				// Country Lookup (Parallelized as it involves DNS)
				country := getCountryInfo(line, currentProtocol)

				results <- configRes{line: line, country: country, proto: currentProtocol}
			}
		}()
	}

	go func() {
		for _, line := range data {
			// Sanitize before processing (fix &amp; HTML entities, etc.)
			jobs <- sanitizeConfig(line)
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	for res := range results {
		// Standardize the name sequentially to have correct indexing
		cleanLine := standardizeName(res.line, res.proto, len(filtered)+1, res.country)
		filtered = append(filtered, cleanLine)

		countryKey := res.country
		if countryKey == "" {
			countryKey = "Unknown"
		}
		configsByCountry[countryKey] = append(configsByCountry[countryKey], cleanLine)
	}

	return filtered, configsByCountry
}

// standardizeName renames a configuration to a professional format: v2go | 🇩🇪 DE | Protocol | ID
func standardizeName(config string, protocol string, index int, country string) string {
	flag := getFlag(country)
	countryDisplay := ""
	if country != "" {
		if flag != "" {
			countryDisplay = flag + " " + country + " | "
		} else {
			countryDisplay = country + " | "
		}
	}
	newName := fmt.Sprintf("v2go | %s%s | %d", countryDisplay, strings.ToUpper(protocol), index)

	switch protocol {
	case "vmess":
		trimmed := strings.TrimPrefix(config, "vmess://")
		decoded, err := decodeBase64([]byte(trimmed))
		if err != nil {
			return config
		}
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(decoded), &data); err != nil {
			return config
		}
		data["ps"] = newName
		updated, _ := json.Marshal(data)
		return "vmess://" + base64.StdEncoding.EncodeToString(updated)

	case "ssr":
		trimmed := strings.TrimPrefix(config, "ssr://")
		decoded, err := decodeBase64([]byte(trimmed))
		if err != nil {
			return config
		}
		// SSR format: host:port:protocol:method:obfs:base64pass/?obfsparam=...&remarks=base64remarks&...
		parts := strings.Split(decoded, "/?")
		if len(parts) < 1 {
			return config
		}

		mainInfo := parts[0]
		params := ""
		if len(parts) > 1 {
			params = parts[1]
		}

		// Handle remarks in params
		paramList := strings.Split(params, "&")
		newParamList := []string{}
		remarksFound := false
		encodedName := strings.ReplaceAll(base64.StdEncoding.EncodeToString([]byte(newName)), "=", "")

		for _, p := range paramList {
			if strings.HasPrefix(p, "remarks=") {
				newParamList = append(newParamList, "remarks="+encodedName)
				remarksFound = true
			} else if p != "" {
				newParamList = append(newParamList, p)
			}
		}
		if !remarksFound {
			newParamList = append(newParamList, "remarks="+encodedName)
		}

		updatedDecoded := mainInfo + "/?" + strings.Join(newParamList, "&")
		return "ssr://" + strings.ReplaceAll(base64.StdEncoding.EncodeToString([]byte(updatedDecoded)), "=", "")

	default:
		// Standard URL protocols: vless, trojan, ss, hy2, tuic
		// Use simple string manipulation to avoid url.Parse re-encoding userinfo/query
		var body string
		if hi := strings.Index(config, "#"); hi >= 0 {
			body = config[:hi]
		} else {
			body = config
		}
		// Trim trailing whitespace from body (some sources have trailing spaces before #)
		body = strings.TrimRight(body, " \t")
		result := body + "#" + url.PathEscape(newName)
		return result
	}
}

// parseCoreIdentity extracts the Protocol + Host + Port from a config line.
// This allows us to find duplicates that have different names or parameters but point to the same server.
func parseCoreIdentity(config string, protocol string) string {
	config = strings.TrimSpace(config)

	switch protocol {
	case "vmess":
		trimmed := strings.TrimPrefix(config, "vmess://")
		decoded, err := decodeBase64([]byte(trimmed))
		if err != nil {
			return config // Fallback to full string if decoding fails
		}
		var data struct {
			Add  string      `json:"add"`
			Port interface{} `json:"port"` // Use interface because port can be string or int
		}
		if err := json.Unmarshal([]byte(decoded), &data); err != nil {
			return config
		}
		return fmt.Sprintf("vmess://%s:%v", data.Add, data.Port)

	case "ssr":
		trimmed := strings.TrimPrefix(config, "ssr://")
		decoded, err := decodeBase64([]byte(trimmed))
		if err != nil {
			// SSR padding is often weird, try simple trim if padding fails
			return config
		}
		// SSR format: host:port:protocol:method:obfs:base64pass/?obfsparam=...
		parts := strings.Split(decoded, ":")
		if len(parts) >= 2 {
			return fmt.Sprintf("ssr://%s:%s", parts[0], parts[1])
		}
		return config

	default:
		u, err := url.Parse(config)
		if err != nil {
			return config
		}
		host := u.Hostname()
		port := u.Port()
		if host == "" {
			return config
		}
		return fmt.Sprintf("%s://%s:%s", protocol, host, port)
	}
}

func getCountryInfo(config, protocol string) string {
	if geoDB == nil {
		return ""
	}

	host := ""
	switch protocol {
	case "vmess":
		trimmed := strings.TrimPrefix(config, "vmess://")
		decoded, err := decodeBase64([]byte(trimmed))
		if err == nil {
			var data struct {
				Add string `json:"add"`
			}
			json.Unmarshal([]byte(decoded), &data)
			host = data.Add
		}
	case "ssr":
		trimmed := strings.TrimPrefix(config, "ssr://")
		decoded, err := decodeBase64([]byte(trimmed))
		if err == nil {
			parts := strings.Split(decoded, ":")
			if len(parts) > 0 {
				host = parts[0]
			}
		}
	default:
		u, err := url.Parse(config)
		if err == nil {
			host = u.Hostname()
		}
	}

	if host == "" {
		return ""
	}

	// Check cache
	if val, ok := geoCache.Load(host); ok {
		return val.(string)
	}

	// Resolve IP if it's a domain
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := net.LookupIP(host)
		if err == nil && len(ips) > 0 {
			ip = ips[0]
		}
	}

	if ip == nil {
		geoCache.Store(host, "")
		return ""
	}

	record, err := geoDB.Country(ip)
	if err != nil {
		geoCache.Store(host, "")
		return ""
	}

	code := record.Country.IsoCode
	geoCache.Store(host, code)
	return code
}

func getFlag(code string) string {
	if len(code) != 2 {
		return ""
	}
	code = strings.ToUpper(code)
	return string(rune(code[0])+127397) + string(rune(code[1])+127397)
}

func downloadGeoIPDB() error {
	dbPath := "GeoLite2-Country.mmdb"
	if _, err := os.Stat(dbPath); err == nil {
		return nil
	}

	fmt.Println("Downloading GeoIP database...")
	url := "https://raw.githubusercontent.com/6Kmfi6HP/maxmind/main/GeoLite2-Country.mmdb"

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(dbPath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func cleanExistingFiles(base64Folder string) {
	// Remove main files
	os.Remove("AllConfigsSub.txt")
	os.Remove("All_Configs_base64_Sub.txt")

	// Remove split files
	for i := 0; i < 20; i++ {
		os.Remove(fmt.Sprintf("Sub%d.txt", i))
		os.Remove(filepath.Join(base64Folder, fmt.Sprintf("Sub%d_base64.txt", i)))
	}

	// Clean Splitted-By-Country directory
	files, err := os.ReadDir("Splitted-By-Country")
	if err == nil {
		for _, f := range files {
			os.Remove(filepath.Join("Splitted-By-Country", f.Name()))
		}
	}
}

func writeCountryFiles(configsByCountry map[string][]string) {
	countryDir := "Splitted-By-Country"
	for country, configs := range configsByCountry {
		filename := filepath.Join(countryDir, country+".txt")
		file, err := os.Create(filename)
		if err != nil {
			continue
		}

		writer := bufio.NewWriter(file)
		for _, config := range configs {
			writer.WriteString(config + "\n")
		}
		writer.Flush()
		file.Close()
	}
}

func writeMainConfigFile(filename string, configs []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// Write fixed text
	if _, err := writer.WriteString(fixedText); err != nil {
		return err
	}

	// Write configs
	for _, config := range configs {
		if _, err := writer.WriteString(config + "\n"); err != nil {
			return err
		}
	}

	return nil
}

func splitIntoFiles(base64Folder string, configs []string) error {
	numFiles := (len(configs) + maxLinesPerFile - 1) / maxLinesPerFile

	// Reverse configs so newest go into Sub1, Sub2, etc.
	reversedConfigs := make([]string, len(configs))
	for i, config := range configs {
		reversedConfigs[len(configs)-1-i] = config
	}

	for i := 0; i < numFiles; i++ {
		// Create custom header for this file
		profileTitle := fmt.Sprintf("🆓 Git:DanialSamadi | Sub%d 🔥", i+1)
		encodedTitle := base64.StdEncoding.EncodeToString([]byte(profileTitle))
		customFixedText := fmt.Sprintf(`#profile-title: base64:%s
#profile-update-interval: 1
#support-url: https://github.com/Danialsamadi/v2go
#profile-web-page-url: https://github.com/Danialsamadi/v2go
`, encodedTitle)

		// Calculate slice bounds (using reversed configs)
		start := i * maxLinesPerFile
		end := start + maxLinesPerFile
		if end > len(reversedConfigs) {
			end = len(reversedConfigs)
		}

		// Write regular file (in current directory)
		filename := fmt.Sprintf("Sub%d.txt", i+1)
		if err := writeSubFile(filename, customFixedText, reversedConfigs[start:end]); err != nil {
			return err
		}

		// Read the file and create base64 version
		content, err := os.ReadFile(filename)
		if err != nil {
			return err
		}

		base64Filename := filepath.Join(base64Folder, fmt.Sprintf("Sub%d_base64.txt", i+1))
		encodedContent := base64.StdEncoding.EncodeToString(content)
		if err := os.WriteFile(base64Filename, []byte(encodedContent), 0644); err != nil {
			return err
		}
	}

	return nil
}

func writeSubFile(filename, header string, configs []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// Write header
	if _, err := writer.WriteString(header); err != nil {
		return err
	}

	// Write configs
	for _, config := range configs {
		if _, err := writer.WriteString(config + "\n"); err != nil {
			return err
		}
	}

	return nil
}

func calculateStats(configs []string) map[string]int {
	stats := make(map[string]int)
	for _, config := range configs {
		for _, protocol := range protocols {
			if strings.HasPrefix(config, protocol) {
				stats[protocol]++
				break
			}
		}
	}
	return stats
}

func writeUpdateSummary(total int, stats map[string]int, duration float64, originalTotal int, failedLinks []string) {
	summaryPath := "UPDATE_SUMMARY.md"

	file, err := os.Create(summaryPath)
	if err != nil {
		fmt.Printf("Error creating summary file: %v\n", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	writer.WriteString("# V2Ray Config Update Summary\n")
	writer.WriteString(fmt.Sprintf("Generated on: %s\n\n", time.Now().Format("2006-01-02 15:04:05 MST")))

	writer.WriteString("## Configuration Statistics\n")
	writer.WriteString(fmt.Sprintf("- Total unique configurations: %d\n", total))
	writer.WriteString("- Protocol breakdown:\n")

	// Sort protocols for consistent output
	for _, p := range protocols {
		count := stats[p]
		writer.WriteString(fmt.Sprintf("  - %s: %d configs\n", p, count))
	}

	writer.WriteString("\n## Performance\n")
	writer.WriteString(fmt.Sprintf("- Processing time: %.2f seconds\n", duration))
	if originalTotal > 0 {
		reduction := float64(originalTotal-total) / float64(originalTotal) * 100
		writer.WriteString(fmt.Sprintf("- Duplicate removal: %.1f%% reduction (from %d to %d)\n", reduction, originalTotal, total))
	}

	if len(failedLinks) > 0 {
		writer.WriteString("\n## ⚠️ Failed Links (404 or Errors)\n")
		writer.WriteString("The following sources could not be reached or returned no data:\n")
		for _, link := range failedLinks {
			writer.WriteString(fmt.Sprintf("- %s\n", link))
		}
	} else {
		writer.WriteString("\n## ✅ All Sources Successful\n")
		writer.WriteString("All configured sources were reached successfully.\n")
	}
}

func checkPort(host, port string) bool {
	if host == "" || port == "" {
		return false
	}
	address := net.JoinHostPort(host, port)
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func getHostPort(config, protocol string) (string, string) {
	switch protocol {
	case "vmess":
		trimmed := strings.TrimPrefix(config, "vmess://")
		decoded, err := decodeBase64([]byte(trimmed))
		if err == nil {
			var data struct {
				Add  string      `json:"add"`
				Port interface{} `json:"port"`
			}
			json.Unmarshal([]byte(decoded), &data)
			return data.Add, fmt.Sprintf("%v", data.Port)
		}
	case "ssr":
		trimmed := strings.TrimPrefix(config, "ssr://")
		decoded, err := decodeBase64([]byte(trimmed))
		if err == nil {
			parts := strings.Split(decoded, ":")
			if len(parts) >= 2 {
				return parts[0], parts[1]
			}
		}
	default:
		u, err := url.Parse(config)
		if err == nil {
			return u.Hostname(), u.Port()
		}
	}
	return "", ""
}
