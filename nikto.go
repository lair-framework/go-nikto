/*Package nikto parses Nikto XML data into a similary formed struct.*/
package nikto

import (
	"encoding/xml"
)

// NiktoData contains all the data from a single nikto scan.
type NiktoData struct {
	XMLName   xml.Name `xml:"niktoscan"`
	NiktoScan []Scan   `xml:"niktoscan"`
}

type Scan struct {
	HostsTest        string       `xml:"hoststest,attr"`
	Options          string       `xml:"options,attr"`
	Version          string       `xml:"version,attr"`
	ScanStart        string       `xml:"scanstart,attr"`
	ScanEnd          string       `xml:"scanend,attr"`
	ScanElapsed      string       `xml:"scanelapsed,attr"`
	XMLOutputVersion string       `xml:"nxmlversion,attr"`
	ScanDetails      []ScanDetail `xml:"scandetails"`
}

// ScanDetails contains all the information for a single host scan.
type ScanDetail struct {
	TargetIP       string     `xml:"targetip,attr"`
	TargetHostname string     `xml:"targethostname,attr"`
	TargetPort     int        `xml:"targetport,attr"`
	TargetBanner   string     `xml:"targetbanner,attr"`
	StartTime      string     `xml:"starttime,attr"`
	SiteName       string     `xml:"sitename,attr"`
	SiteIP         string     `xml:"siteip,attr"`
	HostHeader     string     `xml:"hostheader,attr"`
	Errors         int        `xml:"errors,attr"`
	Checks         int        `xml:"checks,attr"`
	SSL            SSL        `xml:"ssl"`
	Items          []Item     `xml:"item"`
	Statistics     Statistics `xml:"statistics"`
}

// SSL contains the SSL cipher information
type SSL struct {
	Ciphers string `xml:"ciphers,attr"`
	Issuers string `xml:"issuers,attr"`
	Info    string `xml:"info,attr"`
}

// Item contains the nikto finding results
type Item struct {
	ID          int    `xml:"id,attr"`
	OSVDBID     int    `xml:"osvdbid,attr"`
	OSVDBIDLink string `xml:"osvdbidlink,attr"`
	Method      string `xml:"method,attr"`
	Description string `xml:"description"`
	URI         string `xml:"uri"`
	NameLink    string `xml:"namelink"`
	IPLink      string `xml:"iplink"`
}

// Statistics contains the final scan statistics
type Statistics struct {
	Elapsed     string `xml:"elapsed,attr"`
	ItemsFound  int    `xml:"itemsfound,attr"`
	ItemsTested int    `xml:"itemstested,attr"`
	EndTime     string `xml:"endtime,attr"`
}

// Parse takes a byte array of nikto xml data and unmarshals it into an
// NiktoData struct. All elements are returned as strings, it is up to the caller
// to check and cast them to the proper type.
func Parse(content []byte) (*NiktoData, error) {
	r := &NiktoData{}
	err := xml.Unmarshal(content, r)
	if err != nil {
		return r, err
	}
	return r, nil
}
