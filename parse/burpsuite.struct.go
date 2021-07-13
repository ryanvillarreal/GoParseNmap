/* Package Burp Suite parses Nmap XML data into a similary formed struct.

*/
package parse

import (
   "encoding/xml"
   )


// BurpRun contains all the data for a single nmap scan.
type BurpRun struct {
   Items        []Item         `xml:"item" json:"item"`
}

// Item contains info about <xx>
type Item struct {
   Time              string    `xml:"time" json:"time"`
   Url               string    `xml:"url" json:"url"`
   Host              string    `xml:"host" json: "ip"`
   Port              int       `xml:"port" json:"port"`
   Protocol          string    `xml:"protocol" json:"protocol"`
   Method            string    `xml:"method" json:"method:`
   Path              string    `xml:"path" json:"path"`
   Ext               string    `xml:"extension" json:"extension"`
   Request           string    `xml:"request" json:"request"`
   Status            int       `xml:"status" json:"status"`
   ResponseLength    int       `xml:"responselength" json:"responselength"`
   MimeType          string    `xml:"mimetype" json:"mimetype"`
   Response          string    `xml:"response" json:"response"`
   Comment           string    `xml:"comment" json:"comment"`
}

// Parse takes a byte array of Burp Suite xml data and unmarshals it into an
// BurpRun struct. All elements are returned as strings, it is up to the caller
// to check and cast them to the proper type.
func ParseBurp(content []byte) (*BurpRun, error) {
   r := &BurpRun{}
   err := xml.Unmarshal(content, r)
   return r, err
}