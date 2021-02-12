package jwt

import (
	"testing"
)

func TestJwt(t *testing.T) {

	jt := new(TokenTools)

	token, err := jt.CreateToken("liubin")
	if err != nil {
		t.Error(err)
	}
	t.Log("create:", token)
	rs, err := jt.CheckToken(token.Token)
	if err != nil {
		t.Error(err)
	}
	t.Log("check:", rs)

}
