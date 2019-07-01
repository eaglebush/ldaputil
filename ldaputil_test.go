package ldaputil

import (
	"fmt"
	"testing"
)

func TestGetUserAccountControlFlags(t *testing.T) {
	res := GetUserAccountControlFlags("514")
	fmt.Print(res)
}

func TestIsAccountControlDisabled(t *testing.T) {
	res := IsAccountControlDisabled("514") //514 - barry, 66048 - zaldy
	fmt.Print(res)
}

func TestParseUserDomain(t *testing.T) {
	u := "VDIMDCI\\zaldy.baguinon"

	hasdomain, domain, user := ParseUserDomain(&u)
	fmt.Print(hasdomain, domain, user)
}
