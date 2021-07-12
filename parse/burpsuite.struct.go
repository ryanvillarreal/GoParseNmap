/* Package Burp Suite parses Nmap XML data into a similary formed struct.
 
   I was trying to create the structs by hand... by myself and it didn't
   go well... so I found this project where quite a few individuals had been
   working on it. They probably know more than me. 
   https://github.com/lair-framework/go-nmap
   https://pkg.go.dev/github.com/tomsteele/go-nmap#Parse

*/
package parse

// import (
// 	"encoding/xml"
// 	"strconv"
// 	"time"
// )

// type BurpItems struct{

// 	BurpVersion	string	`xml:"items"`
// }