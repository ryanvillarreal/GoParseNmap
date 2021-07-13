# goparse
Extracts information from Nmap/Burp XML files quickly. 
v0.03

**Table of Contents**
- [goparse](#goparse)
  - [Examples](#Examples)
  - [Usage] (#Usage)
  - [Changelog] (#Changelog)
  - [ToDo] (#ToDO)
  - [Contribute] (#Contribute)
  - [Installation] (#Installation)

## Examples

Examples here

## Usage

   Usage: `./goparse [COMMAND]... --file <nmap-xml-output>`
  
   Available Commands: 
   nmap [n]       Allows access to the Nmap subcommands
   burp [b]       Allows access to the Burp subcommands


### Nmap Subcommands
```
   all-hosts      Retrieves all Hosts that were scanned with Nmap.
   
   all-ports      Retrieves all ports that were found with Nmap.
   
   banner         Retrieves a list of all ports with a specific service taht are open. Requires a search flag.
   
   blocked-ports  Retrieves all ports that were found with Nmap.
   
   host-ports     Retrieves the time the Nmap scan stopped.
   
   hosts          Retrieves all hosts with at least one port open.
   
   http-info      Generates a line separated list of all HTTP(s) ports.
   
   http-ports     Generates a line separated list of all HTTP(s) ports.
   
   nmap-cmdline   Retrieves the Arguments used for the Nmap scan.
   
   smb-hosts      Retrieves a list of all hosts with SMB open.
   
   smb-message    Retrieves a list of all hosts with SMB open AND Message Signing Disabled.
   
   start-time     Retrieves the time the Nmap scan started.
   
   stop-time      Retrieves the time the Nmap scan stopped.
   
   testing        used for testing purposes
   
   up-hosts       Retrieves all Hosts that were considered 'Up' by Nmap.
   
   up-ports       Retrieves all ports that were found with Nmap.
   
   version        Retrieves the Version of Nmap used to perform the scan.
   
   help, h        Shows a list of commands or help for one command
```

### Burp Subcommands
 ```
   version        Retrieves the Version of Burp Suite used to test

   mime-search    Retrieves unique list of URLs with the specified MIME type
 ```

  
## Changelog
  - v.03
      - Updated to urfave/cli/v2
      - Aaron added ability to get output of service names
      - Added the ability to search for a service name and get a list of IPs in return
      - Added basic Burp Suite XML parsing for Version and MIME type search   

## ToDo
1. Glob support for multiple file ingestion 
2. Clean up documenation
3. Build for multiple architecture types
4. Request by @deadjakk - ability to intake a blob of data and return various format outputs (i.e. - IPs, Mimikatz output, Email, Domains)

## Contribute

### Adding New Commands

## Installation

Download the binary and GO!

Requirements: 
* Golang (if building from source)

Check out the repository and run it: 
  ```
  git clone https://github.com/ryanvillarreal/goparse
  cd goparse
  go build . 
  ./goparse
  ```
  
Check out with Go Get: 
 ```
  go get github.com/ryanvillarreal/goparse
 ```
  
