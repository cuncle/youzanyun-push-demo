package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

/*
Event-Sign：防伪签名 ：MD5(client_id+entity+client_secret) ; 其中 entity 是从 RequestBody 读取的内容（详情见下文解析示例）
详细推荐文档：https://doc.youzanyun.com/resource/develop-guide/41355/41536
*/

type Youzanclient struct {
	Client_id     string
	Client_secret string
}
type RetMessage struct {
	Code string `json:"code"`
	Msg  string `json:"msg"`
}

func md5sign(str string) string {
	h := md5.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

// 构建一个 youzanclient 的对象
func New(client_id, client_secret string) *Youzanclient {
	return &Youzanclient{client_id, client_secret}
}

// 计算签名 client_id + entity + client_secret 用户计算防伪签名 event-Sign

func (ath *Youzanclient) Verifysign(r *http.Request) (result string) {
	event_sign := r.Header.Get("Event-Sign")
	if event_sign == "" {
		return "fail,no Event_Sign"
	}
	req, _ := ioutil.ReadAll(r.Body)
	//MD5(client_id+entity+client_secret)
	md5string := ath.Client_id + string(req) + ath.Client_secret
	fmt.Println(md5sign(md5string))
	if md5sign(md5string) == event_sign {
		return "sucess"
	} else {
		return "sign_fail"
	}

}

func YouzanPush(w http.ResponseWriter, r *http.Request) {
	//如何查看 client_id 和 client_secret 参考：https://developers.youzanyun.com/article/1556850068966
	client := New("your_client_id ", "your_client_secret")
	result := client.Verifysign(r)
	w.Header().Set("Content-Type", "application/json")
	if result == "sucess" {
		// 校验消息合法以后，返回接收成功标识，然可以处理自己的逻辑解析body
		json.NewEncoder(w).Encode(RetMessage{"200", "success"})
	} else {
		json.NewEncoder(w).Encode(RetMessage{"200", client.Verifysign(r)})
	}

}

func main() {

	http.HandleFunc("/", YouzanPush)
	http.ListenAndServe(":8888", nil)

}
