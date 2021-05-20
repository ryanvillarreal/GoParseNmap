# goparse
Extracts information from Nmap XML files quickly. 

**Table of Contents**
- [goparse](#goparse)
  - [Examples](#examples)
  - [Usage] (#usage)
  - [Changelog] (#changelog)
  - [ToDo] (#todo)
  - [Contribute] (#contribute)

## Examples

Examples here

## Usage

  Usage: `./GoParseNmap [COMMAND]... --file <nmap-xml-output>`
  
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

  
## Changelog


## ToDo
1. Glob support for multiple file ingestion 
2. Clean up documenation
3. Build for multiple architecture types
4. Functionality needs

## Contribute

### Adding New Commands

## Installation

Download the binary and GO!

Requirements: 
* Golang (if building from source)

Check out the repository and run it: 
  ```
  git clone https://github.com/ryanvillarreal/GoParseNmap
  cd GoParseNmap
  git build . 
  ./GoParseNmap
  ```
  
Check out with Go Get: 
```
  go get github.com/ryanvillarreal/GoParseNmap
 ```
  
