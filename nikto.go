/*Package nikto parses Nikto XML data into a similary formed struct.*/
package nikto

import (
	"encoding/xml"
)

// NiktoRun contains all the data from a single nikto scan.
type NiktoRun struct {
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
	SSL        SSL        `xml:"ssl"`
	Items      []Item     `xml:"item"`
	Statistics Statistics `xml:"statistics"`
}

// SSL contains the SSL cipher information
type SSL struct {
	Ciphers string `xml:"ciphers,attr"`
	Issuers string `xml:"issuers,attr"`
	Info    string `xml:"info,attr"`
}

// Item contains the nikto finding results
type Item struct {
	Description string `xml:"description"`
	URI         string `xml:"uri"`
	NameLink    string `xml:"namelink"`
	IPLink      string `xml:"iplink"`
}

// Statistics contains the final scan statistics
type Statistics struct {
	Elapsed    string `xml:"elapsed,attr"`
	ItemsFound string `xml:"itemsfound,attr"`
	EndTime    string `xml:"endtime,attr"`
}

// Parse takes a byte array of nikto xml data and unmarshals it into an
// NiktoRun struct. All elements are returned as strings, it is up to the caller
// to check and cast them to the proper type.
func Parse(content []byte) (*NiktoRun, error) {
	r := &NiktoRun{}
	err := xml.Unmarshal(content, r)
	if err != nil {
		return r, err
	}
	return r, nil
}
