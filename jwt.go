/**
@File:token_tools
@Author:LIUBIN
@Mail:liubin@wxjt.com.cn
@Time:19-8-18 下午2:03
@Software:GoLand
*/

//错误怠慢四、五位 02

/**
This file is a collection of tools for jwt functions
*/
package jwt

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"

	// "github.com/go-redis/redis"
	"time"
)

//define secertkey of jwt
// const (
// secert = "sumgprinting"
// )

// A JWT Token.  Different fields will be used depending on whether you're
// creating or parsing/verifying a token.
// type Token struct {
// Raw       string                 // The raw token.  Populated when you Parse a token
// Method    SigningMethod          // The signing method used or to be used
// Header    map[string]interface{} // The first segment of the token
// Claims    Claims                 // The second segment of the token
// Signature string                 // The third segment of the token.  Populated when you Parse a token
// Valid     bool                   // Is the token valid?  Populated when you Parse/Verify a token
// }

//define TokenTools Class
// type TokenTools struct {
// }
//
//function in TokenTools Class
//生成一个jwt标准的token
// func (this *TokenTools) CreateToken(tp string, user string, domain string, secert string, expire time.Duration) (*JwtResult, error) {
func CreateToken(tp string, user string, domain string, secert string, expire time.Duration) (*JwtResult, error) {
	var err error
	tc := new(TokenContext)
	rs := new(JwtResult)
	rs.Token = tc
	rs.Token.User = user

	//生成一个Token的指针
	token := jwt.New(jwt.SigningMethodHS256)
	//Token中claims信息
	claims := make(jwt.MapClaims)
	claims["username"] = user
	claims["domain"] = domain
	claims["type"] = tp
	// claims["exp"] = time.Now().Add(time.Hour * 24 * time.Duration(1)).Unix()
	claims["exp"] = time.Now().Add(expire).Unix()
	fmt.Println(time.Now().Add(expire))
	claims["iat"] = time.Now().Unix()
	token.Claims = claims
	//加入安全码再次加密
	rs.Token.TokenOrCode, err = token.SignedString([]byte(secert))
	// 错误返回
	if err != nil {
		rs.ErrCode = -1
		rs.ErrMsg = err.Error()
		rs.Valid = false
		return rs, errors.Wrap(err, "create jwt token error :")
	}
	// 成功返回
	rs.ErrCode = 0
	rs.ErrMsg = "ok"
	rs.Valid = true
	return rs, nil
}

//function in TokenTools Class
//验证参数中传来的token是否正确
// func (this *TokenTools) CheckToken(tokenString string, secert string) (*JwtResult, error) {
func CheckToken(tokenString string, secert string) (*JwtResult, error) {
	//eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NjUwNzc2NzksImlhdCI6MTU2NTA3NDA3OSwidXNlcm5hbWUiOiIxMTEifQ.9wwXByWvuhZJ3vmMyJi6znbTjpkzIcxfUGSK_ltE__Q
	// 结果初始化
	tc := new(TokenContext)
	rs := new(JwtResult)
	rs.Token = tc
	rs.ErrCode = 0
	rs.ErrMsg = "ok"
	rs.Valid = true
	rs.Token.TokenOrCode = tokenString
	rs.Token.User = ""
	// 解析jwt-token
	jwtParsed, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secert), nil
	})
	fmt.Println(jwtParsed)
	rs.Valid = jwtParsed.Valid
	// 错误处理
	if err != nil {
		rs.ErrCode = -2
		rs.ErrMsg = err.Error()
		return rs, errors.Wrap(err, "err of Parse jwt")
	}
	// 非法token处理
	if !jwtParsed.Valid {
		rs.ErrCode = -3
		rs.ErrMsg = "invalid token"
		return rs, errors.New("invalid token")
	}
	// 获取解析出的用户名
	rs.Token.User, _ = jwtParsed.Claims.(jwt.MapClaims)["username"].(string)
	rs.Token.Domain, _ = jwtParsed.Claims.(jwt.MapClaims)["domain"].(string)
	rs.Token.Type, _ = jwtParsed.Claims.(jwt.MapClaims)["type"].(string)

	return rs, nil
}
