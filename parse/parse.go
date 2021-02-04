/*
	All parsing functions should take the filename as a string and not be returnable. 
	The entirety of functionality will take place within here. 

	nmapstruct.go ContainsInt the Struct definitions for the XML files.
*/
package parse

import(
	"fmt"
	"encoding/xml"
	"io/ioutil"
	"strings"
	"os"
	"sort"
	"strconv"
)


// PrepWork helps to simplify the code base by performing the byteValue open
// and then unmarshals the XML and sends it back to the relevant function
func PrepWork(filename string) Nmaprun {
	// need to open the XML file as a byte array
	byteValue, _ := ioutil.ReadFile(filename)
	// // fmt.Println(byteValue)
	// // initialize our Nmap array? 
	data := Nmaprun{}
	xml.Unmarshal(byteValue, &data)
	// once the XML is unmarshalled pass back to the individual
	// function to specify the data to be extracted.
	return data
}

// ContainsInt will check a slice for a unique value and will append if not within
func ContainsInt(s []int,e int) bool{
	for _, a := range s {
        if a == e {
            return true
        }
    }
    return false
}

// ContainsStr will check a slice for a unique value and will append if not within
func ContainsStr(s []string,e string) bool{
	for _, a := range s {
        if a == e {
            return true
        }
    }
    return false
}

// MultiLine will take in an int slice convert back to a multi-line list for further testing
func MultiLine(s []int){
	sort.Ints(s)
	for i := 0; i < len(s); i++{
		fmt.Println(s[i])
	}
}

// MultiLine will take in an int slice convert back to a multi-line list for further testing
func MultiLineStr(s []string){
	sort.Strings(s)
	for i := 0; i < len(s); i++{
		fmt.Println(s[i])
	}
}



// FILE INFORMATION ------------------------------------------------------------

// GetVersion prints the version of Nmap used
func GetVersion(filename string){

}


// Get Arguments currently returns the Arguments passed when executing the Nmap Script
func GetArguments(filename string){

}


// GetStart currently returns the Nmaprun Start Date Attribute
func GetStartTime(filename string){

}

// GetStopTime currently returns the Nmaprun Finished Attribute for Stop Date and Time 
func GetStopTime(filename string){

}


// HOST INFORMATION ------------------------------------------------------------


// GetUpHosts will return only hosts that were reported by Nmap as "UP"
// might get some False Positives so I'm going to add another function for
// only IPs with at least 1 port open.
func GetUpHosts(filename string){

}

// GetHostsWithOpenPorts will return IP addresses that were scanned that
// had at least one port open.
func GetHostsWithOpenPorts(filename string){

}

// GetHosts will return a list of all IP addresses that have at least one port open
func GetHosts(filename string){

}


// PORT INFORMATION -----------------------------------------------------------

// BannerSearch will retrieve the Service Name as reported by Nmap
// will only return services that are reported as "open"
func BannerSearch(filename string, search string){

}

// GetSMB will retrieve all hosts with SMB reported as "open"
func GetSMB(filename string){

}

// GetSMBMessage will retrieve all hsots with SMB reported as "open" and Message Signing Disabled
func GetSMBMessage(filename string){

}

// GetHostPorts will return a list of all ports identified by Nmap that have a state of "open"
// format will be multiline IP:Port 
func GetHostPorts(filename string){

}

// GetUpPorts will return a list of all ports identified by Nmap that have a state of "open"
// Some False Positives will exist since some states might be filtered
func GetUpPorts(filename string){

}

// GetUpPorts will return a list of all ports identified by Nmap that have a state of "open"
// Some False Positives will exist since some states might be filtered
func GetBlockedPorts(filename string){

}

// GetPorts will return a list of all ports identified by 
// Some False Positives will exist since some states might be filtered
func GetAllPorts(filename string){

}

