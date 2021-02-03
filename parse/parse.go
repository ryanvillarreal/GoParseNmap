/*
	All parsing functions should take the filename as a string and not be returnable. 
	The entirety of functionality will take place within here. 

	nmapstruct.go contains the Struct definitions for the XML files.
*/
package parse

import(
	"fmt"
	"encoding/xml"
	"io/ioutil"
	"strings"
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


// FILE INFORMATION ------------------------------------------------------------

// GetVersion prints the version of Nmap used
func GetVersion(filename string){
	data := PrepWork(filename)
	version := data.Version
	fmt.Println("Nmap Version: " + version)
}


func GetArguments(filename string){
	data := PrepWork(filename)
	arguments := data.Args
	fmt.Println("Nmap Arguments: " + arguments)
}

func GetStartTime(filename string){
	data := PrepWork(filename)
	fmt.Println("Nmap Start Time: " + data.StartTime)
}

func GetStopTime(filename string){
	data := PrepWork(filename)
	fmt.Println("Nmap Stop Time: " + data.StartTime)
}



// HOST INFORMATION ------------------------------------------------------------


// GetHosts will generate a list of all hosts with open ports. Can be used to perform an additional scan on 
// this host. 
func GetHosts(filename string){
	data := PrepWork(filename)
	// just dump them all
	fmt.Println("Hosts Scanned: ")
	for i := 0; i < len(data.Hosts); i++{
		fmt.Println(data.Hosts[i].Address.Addr)
	}
}

// GetUpHosts will return only hosts that were reported by Nmap as "UP"
// might get some False Positives so I'm going to add another function for
// only IPs with at least 1 port open.
func GetUpHosts(filename string){
	data := PrepWork(filename)
	fmt.Println("Hosts Scanned: ")
	for i := 0; i < len(data.Hosts); i++{
		if (strings.ToLower(data.Hosts[i].HostStatus.State) == "up"){
			fmt.Println(data.Hosts[i].Address.Addr)
		}
	}
}

// GetHostsWithOpenPorts will return IP addresses that were scanned that
// had at least one port open.
func GetHostsWithOpenPorts(filename string){
	data := PrepWork(filename)
	fmt.Println("Hosts Scanned: ")
	for i := 0; i < len(data.Hosts); i++{
		fmt.Println(data.Hosts[i].Address.Addr)
	}
}


// PORT INFORMATION -----------------------------------------------------------

func GetBanners(filename string){
	data := PrepWork(filename)
	arguments := data.Args
	fmt.Println("Banners: " + arguments)
}


