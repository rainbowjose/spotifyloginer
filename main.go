package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/nuveo/anticaptcha"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func main() {
	//get args
	args := os.Args[1:]

	//if args provided - dont print
	if len(args) < 1 {
	fmt.Println("------- Useless spotify login tool")
	fmt.Println("------- Use it with args:")
	fmt.Println("------- spotifylogin username(email) password anticaptchakey")
	fmt.Println("------- e.g: spotifylogin.exe blablabla@gmx.us mypassword 54a6165fd3392992d28091bne9d39a2f")
	fmt.Println("------- You can provide a proxy! This is how it works:")
	fmt.Println("------- spotifylogin.exe blablabla@gmx.us mypassword 54a6165fd3392992d28091bne9d39a2f http://127.0.0.1:8888")
	fmt.Println("------- Proxy must be exactly in 'http://*.*.*.*:*' format")
	}

	// check args quantity
	if len(args) < 3{
		panic(fmt.Sprintf("\n\n\n\n******* Provide all needed args, please! *******"))
	}

	//you must know what you provide
	println("------- Username: " + args[0])
	println("------- Password: " + args[1])
	println("------- Anticaptchakey: " + args[2])
	//if proxy arg provided - post them else not, because of out of array
	if len(args) > 3{
	println("------- Proxy: " + args[3])
	}

	//if proxy arg provided - run proxy edition of request
	if len(args) > 3{
		MakeRequest(args[0], args[1], getcap(args[2]), args[3])
	} else
	{
		MakeRequestProxyless(args[0], args[1], getcap(args[2]))
	}
}
//make proxyless request
func MakeRequest(username string, password string, key string, proxylink string) {
	//key := getcap()
	/*
		println("Username: " + username)
		println("Password: " + password)
		println("Anticaptchakey: " + key)
		println("Proxy: " + proxylink)
	*/
	apiUrl := "https://accounts.spotify.com"
	resource := "/en/login"
	data := url.Values{}

	u, _ := url.ParseRequestURI(apiUrl)
	u.Path = resource
	urlStr := u.String() // "https://api.com/user/"

	fmt.Println("urlstr: " + urlStr + " \n")

	//client := &http.Client{}
	r, _ := http.NewRequest("GET", urlStr, strings.NewReader(data.Encode())) // URL-encoded payload
	r.Header.Add("Host", "accounts.spotify.com")
	r.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0")
	r.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	//r.Header.Add("Accept-Encoding", "gzip, deflate, br")
	r.Header.Add("Accept-Language", "en-US,en;q=0.5")
	r.Header.Add("Upgrade-Insecure-Requests", "1")
	//r.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	r.Header.Add("Connection", "keep-alive")
	r.Header.Add("Cache-Control", "max-age=0")

	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		fmt.Println(err)
	}

	timeout := time.Duration(15000000000)

	proxurl, err := url.Parse(proxylink)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(proxurl)

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxurl),
	}

	client := http.Client{
		Jar:       cookieJar,
		Timeout:   timeout,
		Transport: transport,
	}

	resp, err := client.Do(r)
	if err != nil {
		panic(err)
	}
	fmt.Println(resp.Status)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	type ParseBon struct {
		PhoneFeatureEnabled bool          `json:"phoneFeatureEnabled"`
		User                bool          `json:"user"`
		BON                 []int         `json:"BON"`
	}

	bon := ParseBon{}

	_ = json.Unmarshal([]byte(ParseJson(string(body))), &bon)


	//fmt.Println(ParseJson(string(body)))

	//fmt.Println("Unmarshaled: ", bon.BON[2])
	//fmt.Println("Response: " + string(body))


	apiUrl = "https://accounts.spotify.com"
	resource = "/password/login"
	data = url.Values{}
	data.Set("password", password)
	data.Set("username", username)
	data.Set("remember", "true")
	data.Set("recaptchaToken", key)
	data.Set("csrf_token",getCookieByName(resp.Cookies(), "csrf_token"))

	u, _ = url.ParseRequestURI(apiUrl)
	u.Path = resource
	urlStr = u.String() // "https://api.com/user/"

	fmt.Println("urlstr2: " + urlStr + " \n")


	//fmt.Println(getCookieByName(resp.Cookies(), "csrf_token"))
	//client := &http.Client{}
	r, _ = http.NewRequest("POST", urlStr, strings.NewReader(data.Encode())) // URL-encoded payload
	r.Header.Add("Host", "accounts.spotify.com")
	r.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0")
	r.Header.Add("Accept", "application/json, text/plain, */*")
	//r.Header.Add("Accept-Encoding", "gzip, deflate, br")
	r.Header.Add("Accept-Language", "en-US,en;q=0.5")
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	//r.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	r.Header.Add("Connection", "keep-alive")
	r.Header.Add("Referer", "https://accounts.spotify.com/en/login")

	firstbon := bon.BON[2]
	secondbon := firstbon * 42
	bondone := "0|0|" + strconv.Itoa(firstbon) + "|" + strconv.Itoa(secondbon) + "|1|1|1|1"
	base64bon:= base64.StdEncoding.EncodeToString([]byte(bondone))
	//fmt.Println(base64bon)

	cookieURL, _ := url.Parse("https://accounts.spotify.com")
	bonCookie := &http.Cookie{
		Name:   "__bon",
		Value:  base64bon,
		Path:   "/",
		Domain: "accounts.spotify.com",
	}

	var cookies []*http.Cookie
	cookies = append(cookies, bonCookie)

	cookieJar.SetCookies(cookieURL, cookies)



	client = http.Client{
		Jar:       cookieJar,
		Timeout:   timeout,
		Transport: transport,
	}

	resp, _ = client.Do(r)
	fmt.Println(resp.Status)

	//resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	//io.Copy(os.Stderr, resp.Body)
	fmt.Println("Response: " + string(body))
}
func MakeRequestProxyless(username string, password string, key string) {
	//key := getcap()
	/*
		println("Username: " + username)
		println("Password: " + password)
		println("Anticaptchakey: " + key)
		println("Proxy: " + proxylink)
	*/
	apiUrl := "https://accounts.spotify.com"
	resource := "/en/login"
	data := url.Values{}

	u, _ := url.ParseRequestURI(apiUrl)
	u.Path = resource
	urlStr := u.String() // "https://api.com/user/"

	fmt.Println("urlstr: " + urlStr + " \n")

	//client := &http.Client{}
	r, _ := http.NewRequest("GET", urlStr, strings.NewReader(data.Encode())) // URL-encoded payload
	r.Header.Add("Host", "accounts.spotify.com")
	r.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0")
	r.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	//r.Header.Add("Accept-Encoding", "gzip, deflate, br")
	r.Header.Add("Accept-Language", "en-US,en;q=0.5")
	r.Header.Add("Upgrade-Insecure-Requests", "1")
	//r.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	r.Header.Add("Connection", "keep-alive")
	r.Header.Add("Cache-Control", "max-age=0")

	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		fmt.Println(err)
	}

	timeout := time.Duration(15000000000)

	client := http.Client{
		Jar:       cookieJar,
		Timeout:   timeout,
	}

	resp, err := client.Do(r)
	if err != nil {
		panic(err)
	}
	fmt.Println(resp.Status)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	type ParseBon struct {
		PhoneFeatureEnabled bool          `json:"phoneFeatureEnabled"`
		User                bool          `json:"user"`
		BON                 []int         `json:"BON"`
	}

	bon := ParseBon{}

	_ = json.Unmarshal([]byte(ParseJson(string(body))), &bon)


	//fmt.Println(ParseJson(string(body)))

	//fmt.Println("Unmarshaled: ", bon.BON[2])
	//fmt.Println("Response: " + string(body))


	apiUrl = "https://accounts.spotify.com"
	resource = "/password/login"
	data = url.Values{}
	data.Set("password", password)
	data.Set("username", username)
	data.Set("remember", "true")
	data.Set("recaptchaToken", key)
	data.Set("csrf_token",getCookieByName(resp.Cookies(), "csrf_token"))

	u, _ = url.ParseRequestURI(apiUrl)
	u.Path = resource
	urlStr = u.String() // "https://api.com/user/"

	fmt.Println("urlstr2: " + urlStr + " \n")


	//fmt.Println(getCookieByName(resp.Cookies(), "csrf_token"))
	//client := &http.Client{}
	r, _ = http.NewRequest("POST", urlStr, strings.NewReader(data.Encode())) // URL-encoded payload
	r.Header.Add("Host", "accounts.spotify.com")
	r.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0")
	r.Header.Add("Accept", "application/json, text/plain, */*")
	//r.Header.Add("Accept-Encoding", "gzip, deflate, br")
	r.Header.Add("Accept-Language", "en-US,en;q=0.5")
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	//r.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	r.Header.Add("Connection", "keep-alive")
	r.Header.Add("Referer", "https://accounts.spotify.com/en/login")

	firstbon := bon.BON[2]
	secondbon := firstbon * 42
	bondone := "0|0|" + strconv.Itoa(firstbon) + "|" + strconv.Itoa(secondbon) + "|1|1|1|1"
	base64bon:= base64.StdEncoding.EncodeToString([]byte(bondone))
	//fmt.Println(base64bon)

	cookieURL, _ := url.Parse("https://accounts.spotify.com")
	bonCookie := &http.Cookie{
		Name:   "__bon",
		Value:  base64bon,
		Path:   "/",
		Domain: "accounts.spotify.com",
	}

	var cookies []*http.Cookie
	cookies = append(cookies, bonCookie)

	cookieJar.SetCookies(cookieURL, cookies)



	client = http.Client{
		Jar:       cookieJar,
		Timeout:   timeout,
	}

	resp, _ = client.Do(r)
	fmt.Println(resp.Status)

	//resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	//io.Copy(os.Stderr, resp.Body)
	fmt.Println("Response: " + string(body))
}



func ParseJson(JsonText string) string {

	//blabla := JsonText
	JsonStringParse := "({.*})"
	//fmt.Println(JsonStringParse)
	reg, err := regexp.Compile(JsonStringParse)

	if err != nil {
		fmt.Println(err)
	}

	return reg.FindString(JsonText)
}

func getcap(ackey string) string{
	// Go to https://anti-captcha.com/panel/settings/account to get your key
	c := &anticaptcha.Client{APIKey: ackey}

	key, err := c.SendRecaptcha(
		"https://accounts.spotify.com/password/login", // url that has the recaptcha
		"6Lfdz4QUAAAAABK1wbAdKww1AEvuJuCTVHoWvX8S", // the recaptcha sitekey
		time.Duration(10) * time.Minute, // anticaptcha timeout
	)
	if err != nil {
		fmt.Println(err)
	}else{
		fmt.Println(key)
	}
	return key
}

func getCookieByName(cookie []*http.Cookie, name string) string {
	cookieLen := len(cookie)
	result := ""
	for i := 0; i < cookieLen; i++ {
		if cookie[i].Name == name {
			result = cookie[i].Value
		}
	}
	return result
}