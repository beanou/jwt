package jwt

type TokenContext struct {
	User        string `json:"user"`
	TokenOrCode string `json:"tokenOrCode"`
	Domain      string `json:"domain"`
	Type        string `json:"type"`
}

type JwtResult struct {
	ErrCode int64         `json:"errCode"`
	ErrMsg  string        `json:"errMsg"`
	Valid   bool          `json:"valid"`
	Token   *TokenContext `json:"tokenContext"`
}
