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

// Contains will check a slice for a unique value and will append if not within
func Contains(s []int,e int) bool{
	for _, a := range s {
        if a == e {
            return true
        }
    }
    return false
}

// MultiLine will take in an int slice convert back to 
func MultiLine(s []int){
	sort.Ints(s)
	for i := 0; i < len(s); i++{
		fmt.Println(s[i])
	}
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
	// create the slice for holding unique ports
	s := make([]int, 0)
	for i := 0; i < len(data.Hosts); i++{
		for j := 0; j < len(data.Hosts[i].PortData); j++{
			if (len(data.Hosts[i].PortData[j].SinglePort)) > 0{
				for k := 0; k < len(data.Hosts[i].PortData[j].SinglePort); k++{
					port_int,err := strconv.Atoi(data.Hosts[i].PortData[j].SinglePort[k].PortID)
					if err != nil{
						fmt.Println("Ruh Roh Raggy")
						os.Exit(0)
					}
					if Contains(s,port_int) == false{
						s = append(s,port_int)
					}
				}
			}
		}
	}
	// convert port strings to ints for proper sorting
	MultiLine(s)
}


// PORT INFORMATION -----------------------------------------------------------

// GetBanners will retrieve the Service Name as reported by Nmap
func GetBanners(filename string){
	data := PrepWork(filename)
	fmt.Println("Banners: " + data.Args)
}


// GetUpPorts will return a list of all ports identified by Nmap that have a state of "open"
// Some False Positives will exist since some states might be filtered
func GetUpPorts(filename string){
	data := PrepWork(filename)
	// create the slice for holding unique ports
	s := make([]int, 0)
	for i := 0; i < len(data.Hosts); i++{
		for j := 0; j < len(data.Hosts[i].PortData); j++{
			if (len(data.Hosts[i].PortData[j].SinglePort)) > 0{
				for k := 0; k < len(data.Hosts[i].PortData[j].SinglePort); k++{
					for l := 0; l < len(data.Hosts[i].PortData[j].SinglePort[k].States); l++{
						if strings.ToLower(data.Hosts[i].PortData[j].SinglePort[k].States[l].StateState) == "open"{
							port_int,err := strconv.Atoi(data.Hosts[i].PortData[j].SinglePort[k].PortID)
							if err != nil{
								fmt.Println("Ruh Roh Raggy")
								os.Exit(0)
							}
							if Contains(s,port_int) == false{
								s = append(s,port_int)
							}
						}
					}
				}
			}
		}
		
	}
	// convert int slice back into a multi-line list for easy formatting options
	MultiLine(s)

}

// GetPorts will return a list of all ports identified by 
// Some False Positives will exist since some states might be filtered
func GetAllPorts(filename string){
	data := PrepWork(filename)
	// create the slice for holding unique ports
	s := make([]int, 0)
	for i := 0; i < len(data.Hosts); i++{
		for j := 0; j < len(data.Hosts[i].PortData); j++{
			if (len(data.Hosts[i].PortData[j].SinglePort)) > 0{
				for k := 0; k < len(data.Hosts[i].PortData[j].SinglePort); k++{
					port_int,err := strconv.Atoi(data.Hosts[i].PortData[j].SinglePort[k].PortID)
					if err != nil{
						fmt.Println("Ruh Roh Raggy")
						os.Exit(0)
					}
					if Contains(s,port_int) == false{
						s = append(s,port_int)
					}
				}
			}
		}
	}
	// convert port strings to ints for proper sorting
	MultiLine(s)
}

