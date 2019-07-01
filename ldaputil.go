package ldaputil

import (
	"strconv"
	"strings"
)

var bits map[string]int32

func initbits() {
	bits = map[string]int32{
		`27`: 1, `26`: 2, `25`: 4, `24`: 8, `23`: 16,
		`22`: 32, `21`: 64, `20`: 128, `19`: 256, `18`: 512,
		`17`: 1024, `16`: 2048, `15`: 4096, `14`: 8192,
		`13`: 16328, `12`: 32768, `11`: 65536, `10`: 131072,
		`9`: 262144, `8`: 524288, `7`: 1048576, `6`: 2097152,
		`5`: 4194304, `4`: 8388608, `3`: 16777216, `2`: 33554432, `1`: 67108864,
	}
}

//GetUserAccountControlFlags - get user account flags
func GetUserAccountControlFlags(uacode string) []int32 {
	initbits()

	iuacode, _ := strconv.ParseInt(uacode, 10, 32)
	binstr := strings.TrimSpace(strconv.FormatInt(iuacode, 2)) /*Format to binary */
	binary := strings.Repeat("0", len(bits)-len(binstr)) + binstr

	//println(iuacode, binstr, binary)

	flags := make([]int32, len(binary))
	for i := 0; i < len(binary); i++ {
		str := string(binary[i])
		if str == "1" {
			flags[i] = bits[strconv.FormatInt(int64(i+1), 10)]
		}
	}
	return flags
}

//IsAccountControlDisabled - checks if  accound is disabled
func IsAccountControlDisabled(uacode string) bool {
	return func(fl []int32) bool {
		for i := 0; i < len(fl); i++ {
			//2 is the disabled flag
			if fl[i] == 2 {
				return true
			}
		}

		return false
	}(GetUserAccountControlFlags(uacode))
}

//ParseUserDomain - parses the domain name and user name from the supplied user account. HasDomain returns false when there is no domain
func ParseUserDomain(UserName *string) (HasDomain bool, Domain string, Name string) {
	udom := ""
	unam := ""
	v := *UserName
	pos := strings.Index(v, `\`)
	if pos != -1 {
		udom = v[:pos]
		unam = v[pos+1:]

		return true, udom, unam
	}

	return false, "", v
}
