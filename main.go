package main

import (
  "fmt"
  "log"
  "github.com/valyala/fasthttp"
  "github.com/buaazp/fasthttprouter"
  "encoding/json"
  // "html/template"
  "github.com/likexian/whois-go"
  "github.com/likexian/whois-parser-go"
  "github.com/PuerkitoBio/goquery"
  "strings"
)

const Port = ":8080"

func main() {
  fmt.Println("created by @samzapata")
  // server connection router with fasthttprouter
  router := fasthttprouter.New()
  // endpoint I
  router.GET("/api/servers/v1/d/:domain", ServerFasthttp)

  log.Fatal(fasthttp.ListenAndServe(Port, router.Handler))
}
// fasthttp request handler
func ServerFasthttp(ctx *fasthttp.RequestCtx) {
  // fetch data of server with the given domain
  j := FetchServerData(ctx.UserValue("domain"))
  fmt.Fprintf(ctx, j)
}

// Build server
type Server struct {
  Servers []Serverslice     `json:"servers"`
  Servers_changed bool      `json:"servers_changed"`
  Ssl_grade string          `json:"ssl_grade"`
  Previous_ssl_grade string `json:"previous_ssl_grade"`
  Logo string               `json:"logo"`
  Title string              `json:"title"`
  Is_down bool              `json:"is_down"`
}
// data per server
type Serverslice struct {
  // Name string               `json:"name"`
  Address string            `json:"address"`
  Ssl_grade string          `json:"ssl_grade"`
  Country string            `json:"country"`
  Owner string              `json:"owner"`
}
// structs to scrape ssl data
type SslServer struct {
  Address, Sslgrade string
}
type SslAnalysis struct {
  Sslservers []SslServer
}

func FetchServerData(domain interface{}) string {
  // scraping
  fmt.Println("===Start Scrape Domain===")
  server_scraped := ScrapeServer(domain.(string))
  fmt.Println("===Finish Scrape Domain===")
  fmt.Println("===Start Scrape SSL===")
  ssl_scraped := ScrapeSSL(domain.(string))
  fmt.Println(ssl_scraped)
  fmt.Println("===Finish Scrape SSL===")
  res := fasthttp.AcquireResponse()
  // variables to build server
  var server Server
  var serverslice Serverslice
  host, _ := whois.Whois(domain.(string))
  h, err_dom := whoisparser.Parse(host)
  var servers = h.Domain.NameServers
  // compare the servers detected with the addresses given from SSL-Labs
  if len(ssl_scraped.Sslservers) == len(servers) {
    for i, v := range ssl_scraped.Sslservers {
      fmt.Printf("==== server %d =====\n", i )
      fmt.Println(v)
      serverslice.Address = v.Address
      serverslice.Ssl_grade = v.Sslgrade
      serverslice.Country = h.Registrant.Country
      serverslice.Owner = h.Registrant.Organization
      fmt.Println("--------------------")
      server.Servers = append(server.Servers, Serverslice(serverslice))
    }
  } else {
    for i, v := range servers {
      fmt.Printf("==== server %d =====\n", i )
      fmt.Println(v)
      serverslice.Address = v
      serverslice.Ssl_grade = ssl_scraped.Sslservers[0].Sslgrade
      serverslice.Country = h.Registrant.Country
      serverslice.Owner = h.Registrant.Organization
      fmt.Println("--------------------")
      server.Servers = append(server.Servers, Serverslice(serverslice))
    }
  }
  // comple data of the server
  if err_dom == nil {
    var creation, update, changed = h.Domain.CreatedDate, h.Domain.UpdatedDate, true
    if creation == update {
      changed = false
    }
    server.Servers_changed = changed
    server.Ssl_grade = ssl_scraped.Sslservers[0].Sslgrade
    server.Previous_ssl_grade = ssl_scraped.Sslservers[0].Sslgrade
    server.Title = server_scraped[0]
    server.Logo = server_scraped[1]
    if res.StatusCode() == fasthttp.StatusInternalServerError {
      server.Is_down = true
    } else {
      server.Is_down = false
    }
  }
  // prepare JSON
  s, _ := json.Marshal(server)

  fmt.Println("======")
  fmt.Println(string(s))
  fmt.Println("======")
  // fmt.Println("who is:")
  // fmt.Println(host)
  return string(s)
}

func ScrapeServer(d string) []string {
  // scrape server
  var s []string
  full_url := "https://www." + d
  res_body := DoRequestResponse(full_url)
  fmt.Println("==============Using GoQuery===========")
  data := res_body.(string)
  doc, errr := goquery.NewDocumentFromReader(strings.NewReader(data))
  if errr != nil {
      log.Fatal(errr)
  }
  logo_shortcut := doc.Find("link[rel='shortcut icon']")
  logo_path, _ := logo_shortcut.Attr("href")
  title := doc.Find("title")
  fmt.Println(logo_path)
  fmt.Println(title.Text())
  s = append(s, title.Text())
  s = append(s, logo_path)
  return s
}

func ScrapeSSL(d string) SslAnalysis {
  var grades string
  var ips string
  var sslanalysis SslAnalysis
  var sslserver SslServer

  fmt.Println("=============scraping ssllabs=============")
  ssllabs_path := "https://www.ssllabs.com/ssltest/analyze.html?d="
  full_path := ssllabs_path + d
  ssl_scan := DoRequestResponse(string(full_path))
  doc, errr := goquery.NewDocumentFromReader(strings.NewReader(ssl_scan.(string)))
  if errr != nil {
      log.Fatal(errr)
  }
  // Get address and ssl_grade.
  // This depends on the SSLLabs response (single or table)
  result := doc.Find("table#multiTable") // 1+ ssl grades report
  if result.Size() > 0 {
    result.Each(func(i int, td *goquery.Selection)  {
      td_ip := td.Find("tbody tr td span.ip")
      td_grade := td.Find("tbody tr td[align='center']")
      // saves ips
      ips = ips + " " + td_ip.Text()
      // saves ssl grades
      grades = grades + " " + td_grade.Text()
    })
    grades_slice := strings.Fields(grades)
    index := 1
    for i, v := range grades_slice {
      if index == i {
        sslserver.Sslgrade = v
        index = index + 2
        fmt.Println(i, v)
      }
    }
    ips_slice := strings.Fields(ips)
    for i, v := range ips_slice {
      sslserver.Address = v
      fmt.Println(i, v)
      sslanalysis.Sslservers = append(sslanalysis.Sslservers, SslServer(sslserver))
    }
    // j, _ := json.Marshal(sslanalysis)
    // fmt.Println(string(j))
    return sslanalysis
  } else {
    // fetch the grade
    result_grade := doc.Find("#gradeA")
    grade_ssl := strings.TrimSpace(result_grade.Text())
    // fetch the ip address
    result_ip := doc.Find(".ip")
    ip_ssl := strings.TrimSpace(result_ip.Text())
    ip_ssl = strings.Trim(ip_ssl, "()")
    // prepare json return
    sslserver.Sslgrade = grade_ssl
    sslserver.Address = ip_ssl
    sslanalysis.Sslservers = append(sslanalysis.Sslservers, SslServer(sslserver))
    fmt.Println("ip: " + ip_ssl)
    fmt.Println("grade ssl: " + grade_ssl)
    // j, _ := json.Marshal(sslanalysis)
    // fmt.Println(string(j))
    return sslanalysis
  }
}

// this function receives an url and gives html
func DoRequestResponse(url string) interface{} {
  fmt.Println("==============Request - Response===========")
  req := fasthttp.AcquireRequest()
  req.SetRequestURI(url)
  res := fasthttp.AcquireResponse()
  err := fasthttp.Do(req, res)
	if err != nil {
		fmt.Printf("Client get failed: %s\n", err)
	}
	if res.StatusCode() != fasthttp.StatusOK {
		fmt.Printf("Expected status code %d but got %d\n", fasthttp.StatusOK, res.StatusCode())
	}
	body := res.Body()
  fmt.Println("successful response!")
  return string(body)
}
