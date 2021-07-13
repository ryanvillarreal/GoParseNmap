/*
	All parsing functions should take the filename as a string and not be returnable. 
	The entirety of functionality will take place within here. 

	nmapstruct.go ContainsInt the Struct definitions for the XML files.
*/
package parse

import(
	"fmt"
	"io/ioutil"
	"strings"
	"os"
	"sort"
	"strconv"
)

// PrepWork helps to simplify the code base by performing the byteValue open
// and then unmarshals the XML and sends it back to the relevant function
func PrepWork(filename string) *NmapRun {
	// need to open the XML file as a byte array
	byteValue, _ := ioutil.ReadFile(filename)
	// // fmt.Println(byteValue)
	// // initialize our Nmap array? 
	data,err := Parse(byteValue)
	if err != nil{
		fmt.Println("Ruh Roh Raggy")
		os.Exit(0)
	}

	// once the XML is unmarshalled pass back to the individual
	// function to specify the data to be extracted.
	return data
}

// PrepWork helps to simplify the code base by performing the byteValue open
// and then unmarshals the XML and sends it back to the relevant function
func BurpPrepWork(filename string) *BurpRun {
	// need to open the XML file as a byte array
	byteValue, _ := ioutil.ReadFile(filename)
	// initialize our Burp array? 
	data,err := ParseBurp(byteValue)
	if err != nil{
		fmt.Println("Ruh Roh Raggy")
		os.Exit(0)
	}

	// once the XML is unmarshalled pass back to the individual
	// function to specify the data to be extracted.
	return data
}

// Contains will check a slice for a unique value and returns a bool if it exists
func Contains(s []int,e int) bool{
	for _, a := range s {
        if a == e {
            return true
        }
    }
    return false
}


// MultiLineInt will take in an int slice convert back to a multi line output
func MultiLineInt(s []int){
	sort.Ints(s)
	for i := 0; i < len(s); i++{
		fmt.Println(s[i])
	}
}

// MultiLineStr will take in an int slice convert back to a single line as a string for ingestion to other tools
func SingleLineInt(s []int){
	sort.Ints(s)
	t := make([]string,0)
	for i := 0; i < len(s); i++{
		t = append(t,strconv.Itoa(s[i])) 
	}
	output := strings.Join(t, `,`)
	fmt.Println(output)
}

// MultiLineStr same as above but now with 100% more strings
func MultiLineStr(s []string){
	sort.Strings(s)
	for i := 0; i < len(s); i++{
		fmt.Println(s[i])
	}
}

// SingleLineStr will take in an string slice convert back to a single line as a string for ingestion to other tools
func SingleLineStr(s []string){
	t := make([]string,0)
	for i := 0; i < len(s); i++{
		t = append(t,s[i]) 
	}
	output := strings.Join(t, `,`)
	fmt.Println(output)
}

// Unique will take a slice and unique it, returning a new slice
func Unique(stringSlice []string) []string {
    keys := make(map[string]bool)
    list := []string{}
    for _, entry := range stringSlice {
        if _, value := keys[entry]; !value {
            keys[entry] = true
            list = append(list, entry)
        }
    }
    return list
}


// Burp Suite Parsing here
// FILE INFORMATION -----------------------------------------------------------
func GetBurpVersion(filename string){
	data := BurpPrepWork(filename)
	fmt.Println(data)
}

func GetMimeType(filename string, search string){
	data := BurpPrepWork(filename)
	s := make([]string, 0)
	for i := 0; i < len(data.Items); i++{
		//fmt.Println(data.Items[i].MimeType)
		if strings.ToLower(data.Items[i].MimeType) == strings.ToLower(search){
			s = append(s,data.Items[i].Url)
		}
	}
	MultiLineStr(Unique(s))	
}


// Nmap Parsing here
// FILE INFORMATION ------------------------------------------------------------

// GetVersion prints the version of Nmap used
func GetVersion(filename string){
	data := PrepWork(filename)
	fmt.Println("Nmap Version: " + data.Version)
}


// Get Arguments currently returns the Arguments passed when executing the Nmap Script
func GetArguments(filename string){
	data := PrepWork(filename)
	fmt.Println(data.Args)
}


// GetStart currently returns the Nmaprun Start Date Attribute
func GetStartTime(filename string){
	data := PrepWork(filename)
	fmt.Println("Start Time: " + data.StartStr)
}

// GetStopTime currently returns the Nmaprun Finished Attribute for Stop Date and Time 
func GetStopTime(filename string){
	data := PrepWork(filename)
	fmt.Println("Stop Time: " + data.RunStats.Finished.TimeStr)
}


// HOST INFORMATION ------------------------------------------------------------


// GetUpHosts will return only hosts that were reported by Nmap as "UP"
// might get some False Positives so I'm going to add another function for
// only IPs with at least 1 port open.
func GetUpHosts(filename string){
	data := PrepWork(filename)
	for i := 0; i < len(data.Hosts); i++{
		if (strings.ToLower(data.Hosts[i].Status.State)) == "up"{
			for j := 0; j < len(data.Hosts[i].Addresses); j++{
				if (strings.ToLower(data.Hosts[i].Addresses[j].AddrType)) == "ipv4"{
					fmt.Println(data.Hosts[i].Addresses[j].Addr)
				}
				if (strings.ToLower(data.Hosts[i].Addresses[j].AddrType)) == "ipv6"{
					fmt.Println(data.Hosts[i].Addresses[j].Addr)
				}

			}
		}
	}
}

// GetHostsWithOpenPorts will return IP addresses that were scanned that
// had at least one port open.
func GetHostsWithOpenPorts(filename string){
	data := PrepWork(filename)
	for i := 0; i < len(data.Hosts); i++{
		for j := 0; j < len(data.Hosts[i].Addresses); j++{
			if (strings.ToLower(data.Hosts[i].Addresses[j].AddrType)) == "ipv4"{
				for k := 0; k < len(data.Hosts[i].Ports); k++{
					if strings.ToLower(data.Hosts[i].Ports[k].State.State) == "open"{
						// Print the IP and move on!
						fmt.Println(data.Hosts[i].Addresses[j].Addr)
						break // break out of the k loop
					}
				}
			}
			if (strings.ToLower(data.Hosts[i].Addresses[j].AddrType)) == "ipv6"{
				for k := 0; k < len(data.Hosts[i].Ports); k++{
					if strings.ToLower(data.Hosts[i].Ports[k].State.State) == "open"{
						// Print the IP and move on!
						fmt.Println(data.Hosts[i].Addresses[j].Addr)
						break // break out of the k loop. 
					}
				}
			}
		}
	}
}

// GetHosts will return a list of all IP addresses that were tested by Nmap
func GetAllHosts(filename string){
	data := PrepWork(filename)
	for i := 0; i < len(data.Hosts); i++{
		for j := 0; j < len(data.Hosts[i].Addresses); j++{
			fmt.Println(data.Hosts[i].Addresses[j].Addr)
		}
	}
}


// hosts-to-port [port]
// Extracts a list of all hosts that have the given port open in 'host (hostname)' format.
func GetHostsPortsProtocol(filename string){
data := PrepWork(filename)
	for i := 0; i < len(data.Hosts); i++{
		for j := 0; j < len(data.Hosts[i].Addresses); j++{
			if (strings.ToLower(data.Hosts[i].Addresses[j].AddrType)) == "ipv4"{
				for k := 0; k < len(data.Hosts[i].Ports); k++{
					if strings.ToLower(data.Hosts[i].Ports[k].State.State) == "open"{
						port_str := strconv.Itoa(data.Hosts[i].Ports[k].PortId)
						protocol := data.Hosts[i].Ports[k].Protocol
						fmt.Println(data.Hosts[i].Addresses[j].Addr + ":" + port_str + " " + protocol)
					}
				}
			}
			if (strings.ToLower(data.Hosts[i].Addresses[j].AddrType)) == "ipv6"{
				for k := 0; k < len(data.Hosts[i].Ports); k++{
					if strings.ToLower(data.Hosts[i].Ports[k].State.State) == "open"{
						// Print the IP and move on!
						port_str := strconv.Itoa(data.Hosts[i].Ports[k].PortId)
						protocol := data.Hosts[i].Ports[k].Protocol
						fmt.Println(data.Hosts[i].Addresses[j].Addr + ":" + port_str + " " + protocol)
					}
				}
			}
		}
	}
}


// 
// hosts-to-port [port]
// Extracts a list of all hosts that have the given port open in 'host (hostname)' format.
func GetHostsToPort(filename string, port int){
	data := PrepWork(filename)
	//s := make([]string, 0)
	for i := 0; i < len(data.Hosts); i++{
		for j := 0; j < len(data.Hosts[i].Addresses); j++{
			if (strings.ToLower(data.Hosts[i].Addresses[j].AddrType)) == "ipv4"{
				for k := 0; k < len(data.Hosts[i].Ports); k++{
						if strings.ToLower(data.Hosts[i].Ports[k].State.State) == "open"{
							if (data.Hosts[i].Ports[k].PortId == port){
								fmt.Println(data.Hosts[i].Addresses[j].Addr, data.Hosts[i].Hostnames[0].Name)
							}
						}
					}
				}
			if (strings.ToLower(data.Hosts[i].Addresses[j].AddrType)) == "ipv6"{
				for k := 0; k < len(data.Hosts[i].Ports); k++{
					if strings.ToLower(data.Hosts[i].Ports[k].State.State) == "open"{
						if (data.Hosts[i].Ports[k].PortId == port){
								fmt.Println(data.Hosts[i].Addresses[j].Addr, data.Hosts[i].Hostnames[0].Name)
							}
					}
				}
			}
		}
	}
}



// PORT INFORMATION -----------------------------------------------------------

// BannerSearch will retrieve the Service Name as reported by Nmap
// will only return services that are reported as "open"
func BannerSearch(filename string, search string){
	data := PrepWork(filename)

	s := make([]string, 0)
	for i := 0; i < len(data.Hosts); i++{
		for j := 0; j < len(data.Hosts[i].Addresses); j++{
			if (strings.ToLower(data.Hosts[i].Addresses[j].AddrType)) == "ipv4"{
				for k := 0; k < len(data.Hosts[i].Ports); k++{
						if strings.ToLower(data.Hosts[i].Ports[k].State.State) == "open"{
							if strings.ToLower(data.Hosts[i].Ports[k].Service.Name) == strings.ToLower(search){
								s = append(s,data.Hosts[i].Addresses[j].Addr)
							}
						}
					}
				}
			if (strings.ToLower(data.Hosts[i].Addresses[j].AddrType)) == "ipv6"{
				for k := 0; k < len(data.Hosts[i].Ports); k++{
					if strings.ToLower(data.Hosts[i].Ports[k].State.State) == "open"{
						if strings.ToLower(data.Hosts[i].Ports[k].Service.Name) == strings.ToLower(search){
								s = append(s,data.Hosts[i].Addresses[j].Addr)
							}
					}
				}
			}
		}
	}
	MultiLineStr(Unique(s))

}

// GetSMB will retrieve all hosts with SMB reported as "open"
func GetSMB(filename string){
	data := PrepWork(filename)
	s := make([]int, 0)
	for i := 0; i < len(data.Hosts); i++{
		for j := 0; j < len(data.Hosts[i].Addresses); j++{
			if (strings.ToLower(data.Hosts[i].Addresses[j].AddrType)) == "ipv4"{
				for k := 0; k < len(data.Hosts[i].Ports); k++{
					if strings.ToLower(data.Hosts[i].Ports[k].State.State) == "open"{
						// find out of the port is 445
						if data.Hosts[i].Ports[k].PortId == 445{
							fmt.Println(data.Hosts[i].Addresses[j].Addr)
						}
					}
				}
			}
			if (strings.ToLower(data.Hosts[i].Addresses[j].AddrType)) == "ipv6"{
				for k := 0; k < len(data.Hosts[i].Ports); k++{
					if strings.ToLower(data.Hosts[i].Ports[k].State.State) == "open"{
						// find out of the port is 445
						if data.Hosts[i].Ports[k].PortId == 445{
							fmt.Println(data.Hosts[i].Addresses[j].Addr)
						}
					}
				}
			}
		}
	}
	MultiLineInt(s)
}

// GetSMBMessage will retrieve all hsots with SMB reported as "open" and Message Signing Disabled
func GetSMBMessage(filename string){
	data := PrepWork(filename)
	for i := 0; i < len(data.Hosts); i++{
		if len(data.Hosts[i].HostScripts) > 0{
			for j := 0; j < len(data.Hosts[i].HostScripts); j++{
				if strings.ToLower(data.Hosts[i].HostScripts[j].Id) == "smb-security-mode"{
					if strings.Contains(strings.ToLower(data.Hosts[i].HostScripts[j].Output), strings.ToLower("dangerous")){
						for k := 0; k < len(data.Hosts[i].Addresses); k++{
							if strings.ToLower(data.Hosts[i].Addresses[k].AddrType) == "ipv4"{
								fmt.Println(data.Hosts[i].Addresses[k].Addr)
							}
							if strings.ToLower(data.Hosts[i].Addresses[k].AddrType) == "ipv6"{
								fmt.Println(data.Hosts[i].Addresses[k].Addr)
							}
						}

					}
				}
				if strings.ToLower(data.Hosts[i].HostScripts[j].Id) == "smb2-security-mode"{
					if strings.Contains(strings.ToLower(data.Hosts[i].HostScripts[j].Output), strings.ToLower("but not")){
						for k := 0; k < len(data.Hosts[i].Addresses); k++{
							if strings.ToLower(data.Hosts[i].Addresses[k].AddrType) == "ipv4"{
								fmt.Println(data.Hosts[i].Addresses[k].Addr)
							}
							if strings.ToLower(data.Hosts[i].Addresses[k].AddrType) == "ipv6"{
								fmt.Println(data.Hosts[i].Addresses[k].Addr)
							}
						}

					}
				}
			}
		}
	}
}

// GetHostPorts will return a list of all ports identified by Nmap that have a state of "open"
// format will be MultiLineInt IP:Port 
func GetHostPorts(filename string){
	data := PrepWork(filename)
	s := make([]int, 0)
	for i := 0; i < len(data.Hosts); i++{
		for j := 0; j < len(data.Hosts[i].Addresses); j++{
			if (strings.ToLower(data.Hosts[i].Addresses[j].AddrType)) == "ipv4"{
				for k := 0; k < len(data.Hosts[i].Ports); k++{
					if strings.ToLower(data.Hosts[i].Ports[k].State.State) == "open"{
						port_str := strconv.Itoa(data.Hosts[i].Ports[k].PortId)
						fmt.Println(data.Hosts[i].Addresses[j].Addr + ":" + port_str)
					}
				}
			}
			if (strings.ToLower(data.Hosts[i].Addresses[j].AddrType)) == "ipv6"{
				for k := 0; k < len(data.Hosts[i].Ports); k++{
					if strings.ToLower(data.Hosts[i].Ports[k].State.State) == "open"{
						port_str := strconv.Itoa(data.Hosts[i].Ports[k].PortId)
						fmt.Println(data.Hosts[i].Addresses[j].Addr + ":" + port_str)
					}
				}
			}
		}
	}
	MultiLineInt(s)
}

// GetUpPorts will return a list of all ports identified by Nmap that have a state of "open"
// todo: put in comma separated list to 
func GetUpPorts(filename string){
	data := PrepWork(filename)
	s := make([]int, 0)
	for i := 0; i < len(data.Hosts); i++{
		for j := 0; j < len(data.Hosts[i].Addresses); j++{
			if (strings.ToLower(data.Hosts[i].Addresses[j].AddrType)) == "ipv4"{
				for k := 0; k < len(data.Hosts[i].Ports); k++{
					if strings.ToLower(data.Hosts[i].Ports[k].State.State) == "open"{
						if Contains(s,data.Hosts[i].Ports[k].PortId) == false{
							s = append(s,data.Hosts[i].Ports[k].PortId)
						}
					}
				}
			}
			if (strings.ToLower(data.Hosts[i].Addresses[j].AddrType)) == "ipv6"{
				for k := 0; k < len(data.Hosts[i].Ports); k++{
					if strings.ToLower(data.Hosts[i].Ports[k].State.State) == "open"{
						if Contains(s,data.Hosts[i].Ports[k].PortId) == false{
							s = append(s,data.Hosts[i].Ports[k].PortId)
						}
					}
				}
			}
		}
	}
	MultiLineInt(s)
}

// GetUpPorts will return a list of all ports identified by Nmap that have a state of "open"
// Some False Positives will exist since some states might be filtered
func GetBlockedPorts(filename string){
data := PrepWork(filename)
	s := make([]int, 0)
	for i := 0; i < len(data.Hosts); i++{
		for j := 0; j < len(data.Hosts[i].Addresses); j++{
			if (strings.ToLower(data.Hosts[i].Addresses[j].AddrType)) == "ipv4"{
				for k := 0; k < len(data.Hosts[i].Ports); k++{
						if strings.ToLower(data.Hosts[i].Ports[k].State.State) == "filtered"{
							if Contains(s,data.Hosts[i].Ports[k].PortId) == false{
								s = append(s,data.Hosts[i].Ports[k].PortId)
							}
						}
						if strings.ToLower(data.Hosts[i].Ports[k].State.State) == "tcpwrapped"{
							if Contains(s,data.Hosts[i].Ports[k].PortId) == false{
								s = append(s,data.Hosts[i].Ports[k].PortId)
							}
						}

					}
				}
			if (strings.ToLower(data.Hosts[i].Addresses[j].AddrType)) == "ipv6"{
				for k := 0; k < len(data.Hosts[i].Ports); k++{
					if strings.ToLower(data.Hosts[i].Ports[k].State.State) == "filtered"{
						if Contains(s,data.Hosts[i].Ports[k].PortId) == false{
							s = append(s,data.Hosts[i].Ports[k].PortId)
						}
					}
					if strings.ToLower(data.Hosts[i].Ports[k].State.State) == "tcpwrapped"{
						if Contains(s,data.Hosts[i].Ports[k].PortId) == false{
							s = append(s,data.Hosts[i].Ports[k].PortId)
						}
					}
				}
			}
		}
	}
	MultiLineInt(s)
}

// GetPorts will return a list of all ports identified by 
// Some False Positives will exist since some states might be filtered
func GetAllPorts(filename string){
	data := PrepWork(filename)
	s := make([]int, 0)
	for i := 0; i < len(data.Hosts); i++{
		for j := 0; j < len(data.Hosts[i].Addresses); j++{
			if (strings.ToLower(data.Hosts[i].Addresses[j].AddrType)) == "ipv4"{
				for k := 0; k < len(data.Hosts[i].Ports); k++{
					if Contains(s,data.Hosts[i].Ports[k].PortId) == false{
						s = append(s,data.Hosts[i].Ports[k].PortId)
					}
				}
			}
			if (strings.ToLower(data.Hosts[i].Addresses[j].AddrType)) == "ipv6"{
				for k := 0; k < len(data.Hosts[i].Ports); k++{
					if Contains(s,data.Hosts[i].Ports[k].PortId) == false{
						s = append(s,data.Hosts[i].Ports[k].PortId)
					}
				}
			}
		}
	}
	SingleLineInt(s)
}

// GetServiceNames will return a list of all port "names" identified by Nmap that have a state of "open"
// Some False Positives will exist since some states might be filtered
func GetServiceNames(filename string){
data := PrepWork(filename)
	s := make([]string, 0)
	for i := 0; i < len(data.Hosts); i++{
		for j := 0; j < len(data.Hosts[i].Addresses); j++{
			if (strings.ToLower(data.Hosts[i].Addresses[j].AddrType)) == "ipv4"{
				for k := 0; k < len(data.Hosts[i].Ports); k++{
						if strings.ToLower(data.Hosts[i].Ports[k].State.State) == "open"{
								s = append(s,data.Hosts[i].Ports[k].Service.Name)
						}
					}
				}
			if (strings.ToLower(data.Hosts[i].Addresses[j].AddrType)) == "ipv6"{
				for k := 0; k < len(data.Hosts[i].Ports); k++{
					if strings.ToLower(data.Hosts[i].Ports[k].State.State) == "open"{
							s = append(s,data.Hosts[i].Ports[k].Service.Name)
					}
				}
			}
		}
	}
	MultiLineStr(Unique(s))
}

// GetHTTPPorts will retrieve the any service regarded as an HTTP service from Nmap
// will only return services that are reported as "open" and in the format http(s)://<ip>:<port>
func GetHTTPPorts(filename string){
	data := PrepWork(filename)
	service := make([]string, 0)
	service = append(service, "http", "https", "http-alt", "http-proxy", "soap", "sip", "rtsp", "vnc-http", "caldav")
	for i := 0; i < len(data.Hosts); i++{
		for j := 0; j < len(data.Hosts[i].Addresses); j++{
			if (strings.ToLower(data.Hosts[i].Addresses[j].AddrType)) == "ipv4"{
				for k := 0; k < len(data.Hosts[i].Ports); k++{
						if strings.ToLower(data.Hosts[i].Ports[k].State.State) == "open"{
								currentService := strings.ToLower(data.Hosts[i].Ports[k].Service.Name)
								for l := 0; l < len(service); l++{
									if currentService == service[l]{
										port_str := strconv.Itoa(data.Hosts[i].Ports[k].PortId)
										fmt.Println("http://" + data.Hosts[i].Addresses[j].Addr + ":" + port_str)
									}
								}
							}
						}
					}
			if (strings.ToLower(data.Hosts[i].Addresses[j].AddrType)) == "ipv6"{
				for k := 0; k < len(data.Hosts[i].Ports); k++{
					if strings.ToLower(data.Hosts[i].Ports[k].State.State) == "open"{
						currentService := strings.ToLower(data.Hosts[i].Ports[k].Service.Name)
						for l := 0; l < len(service); l++{
							if currentService == service[l]{
								port_str := strconv.Itoa(data.Hosts[i].Ports[k].PortId)
								fmt.Println("http://" + data.Hosts[i].Addresses[j].Addr + ":" + port_str)
							}
						}
					}
				}
			}
		}
	}
}