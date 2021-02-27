package jwt

import (
	"testing"
)

func TestJwt(t *testing.T) {

	// jt := new(TokenTools)

	token, err := CreateToken("token", "liubin", "www.sumg.press", "sumgprinting", 7200)
	if err != nil {
		t.Error(err)
	}
	t.Log("create:", token)
	rs, err := CheckToken(token.Token.TokenOrCode, "sumgprinting")
	if err != nil {
		t.Error(err)
	}
	t.Log("check:", rs)
	t.Log(rs.Token)

}
