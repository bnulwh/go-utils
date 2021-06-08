package go_utils

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
)

// Sha1Sum sha1 calc
func Sha1Sum(src string) string {
	h := sha1.New()
	io.WriteString(h, src)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Sha256Sum sha256 calc
func Sha256Sum(src string) string {
	h := sha256.New()
	io.WriteString(h, src)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Md5Sum md5 calc
func Md5Sum(src string) string {
	h := md5.New()
	io.WriteString(h, src)
	return fmt.Sprintf("%x", h.Sum(nil))
}
