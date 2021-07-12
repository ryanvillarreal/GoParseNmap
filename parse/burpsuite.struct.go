/* Package Burp Suite parses Nmap XML data into a similary formed struct.

*/
package parse

import (
   "encoding/xml"
   )


// BurpRun contains all the data for a single nmap scan.
type BurpRun struct {

}


// Parse takes a byte array of Burp Suite xml data and unmarshals it into an
// BurpRun struct. All elements are returned as strings, it is up to the caller
// to check and cast them to the proper type.
func ParseBurp(content []byte) (*BurpRun, error) {
   r := &BurpRun{}
   err := xml.Unmarshal(content, r)
   return r, err
}