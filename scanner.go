// scanner
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Result contains the result of a search.
type Result struct {
	Path    string
	Message string
	Text    string
}

type Pattern struct {
	Regex   string `json:"regex"`
	Message string `json:"message"`
}

var PATTERNS []*Pattern
var EXCLUSIONS []string
var RESULTS []*Result
var START time.Time
var END time.Time

func loadPatterns(path string) ([]*Pattern, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close() // close file when function returns

	var patterns []*Pattern
	err = json.NewDecoder(file).Decode(&patterns)
	return patterns, err
}

func loadPatternsNE(path string) []*Pattern {
	patterns, err := loadPatterns(path)
	if err != nil {
		log.Panicln("Something went wrong calling loadPatterns: %s", err)
	}
	return patterns

}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func readLinesNE(path string) []string {
	lines, err := readLines(path)
	if err != nil {
		log.Panicln("Something when wrong calling readLines: %s", err)
	}
	return lines
}

// Scans source code filesystem for suspected security vulnerabilities
func scan(path string, patternsFile string, exclusionsFile string) error {
	PATTERNS = loadPatternsNE(patternsFile)
	EXCLUSIONS = readLinesNE(exclusionsFile)
	START = time.Now()
	err := filepath.Walk(path, visit)
	END = time.Now()
	return err
}

// Visitor function that is run for each file/directory
func visit(path string, f os.FileInfo, err error) error {
	if !f.IsDir() {
		if !inExceptions(path) {
			err := scanFile(path)
			if err != nil {
				return err
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func scanFile(path string) error {
	for _, pattern := range PATTERNS {
		fmt.Printf("***scan pattern %s\n", pattern.Regex)
		err := grep(pattern, path)
		if err != nil {
			return err
		}
	}
	return nil
}

func grep(pattern *Pattern, path string) error {
	regex, err := regexp.Compile(pattern.Regex)
	if err != nil {
		return err // there was a problem with the regular expression.
	}

	fh, err := os.Open(path)
	f := bufio.NewReader(fh)

	if err != nil {
		return err // there was a problem opening the file.
	}
	defer fh.Close()

	buf := make([]byte, 1024)
	for {
		buf, _, err = f.ReadLine()
		if err != nil {
			if err != io.EOF {
				return err
			} else {
				return nil
			}
		}

		s := string(buf)
		if regex.MatchString(s) {
			fmt.Printf("%s: %s: %s\n", path, pattern.Message, string(buf))
			addResult(path, pattern.Message, string(buf))
		}
	}
	return nil
}

func inExceptions(path string) bool {
	for _, re := range EXCLUSIONS {
		regex, _ := regexp.Compile(re)
		if regex.MatchString(path) {
			return true
		}
	}
	return false
}

func addResult(path string, message string, text string) error {
	result := Result{path, message, text}
	RESULTS = append(RESULTS, &result)
	return nil
}

func displayResults(path string, patternsFile string, exclusionsFile string) error {
	const layout = "Jan 2, 2006 at 3:04pm (MST)"
	fmt.Printf("RESULTS of the scan for %s\n", path)
	fmt.Printf("  patterns file: %s\n", patternsFile)
	fmt.Printf("  exclusions file: %s\n", exclusionsFile)
	fmt.Printf("  start time: %s\n", START.Format(layout))
	fmt.Printf("  duration (seconds): %f\n", END.Sub(START).Seconds())
	return nil
}

// MAIN
func main() {
	flag.Parse()
	path := flag.Arg(0)
	patternsFile := flag.Arg(1)
	exclusionsFile := flag.Arg(2)
	err := scan(path, patternsFile, exclusionsFile)
	fmt.Printf("scan() returned %v\n", err)
	err = displayResults(path, patternsFile, exclusionsFile)
}

//INIT
func init() {
	//fmt.Printf("init() called\n")
}
