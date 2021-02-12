package jwt

type JwtResult struct {
	ErrCode  int64  `json:"errCode"`
	ErrMsg   string `json:"errMsg"`
	Valid    bool   `json:"valid"`
	Username string `json:"username"`
	Token    string `json:"token"`
}
