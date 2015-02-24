// scanner_test
// matching pattern here >> erik <<<
// marc
package main

import (
	"fmt"
	"testing"
)

func TestScanner(t *testing.T) {
	fmt.Println("test: TestScanner")
	err := scan("..", "patterns.txt", "exclusions.txt")
	fmt.Printf("scan() returned %v\n", err)
	err = displayResults("..", "patterns.txt", "exclusions.txt")
}
