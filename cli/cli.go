package cli

import(
    // native imports
    "fmt"
    "net/http"
	"os"
    "time"
    "sort"
    "strconv"
    //"reflect"

    // external imports
    "github.com/urfave/cli/v2"
    "github.com/ryanvillarreal/goparse/parse"
)


// define the variables first.
var(
	filename   string
    unfinished bool
    search     string
    formatType string
    port       int
)

// CheckPort will check to make sure the port is between 1 - 65,535 and then returns an int to be used
func CheckPort(search string) int{
    port := 0
	port, err := strconv.Atoi(search)
    // error out if port provided is not a valid int
    if err != nil {
        // handle errors
        fmt.Println("Ports specified must be a type [int]")
        os.Exit(2)
    }
    if (port >= 1 && port <= 65535){
        return port
    } else{
        fmt.Println("Port must be within the valid range of 1 - 65535")
        os.Exit(2)
    }
    // should never get here, but I guess go requires a return for everything.
    return 0
}

// GetFileContenType will grab the first 512 bytes of the file
// and uses the net/http function DetectContentType to determine
// the incoming file type and returns the file type as a string
func GetFileContentType(out *os.File) (bool) {
	// Only the first 512 bytes are used to sniff the content type.
	buffer := make([]byte, 512)

	_, err := out.Read(buffer)
	if err != nil {
		return false
	}
	// Use the net/http package's handy DectectContentType function. Always returns a valid
	// content-type by returning "application/octet-stream" if no others seemed to match.
	contentType := http.DetectContentType(buffer)

	if contentType != "text/xml; charset=utf-8"{
		fmt.Println("Parsing Nmap requires XML files. Use the -oX or -oA options with Nmap")
		return false
	}
	return true
}

// Run parses command line arguments and checks the incoming
// files content-type to ensure XML file is selected
// Run parses command line arguments and checks the incoming
// files content-type to ensure XML file is selected
func OpenFile(filename string) {

	// Check to see if the file can exists/can be opened
	// Open File
	f, err := os.Open(filename)
	if err != nil {
		fmt.Println("File Path Required")
		os.Exit(0)
	}
	// defer the close to after execution finishes
	defer f.Close()

	// error checking on file type
	if GetFileContentType(f) != true{
		os.Exit(0)
	}
}


// This is basically the entry point for the rest of the program
func CommandLine() {
    // add support for Globs here.

    // Define Base Flags
    baseFlags := []cli.Flag {
          &cli.StringFlag{
            Name:        "file",
            Required: true,
            Destination: &filename,
          },
    }
    // Define extra flags for searching
    extraFlags := []cli.Flag {
          &cli.StringFlag{
            Name:        "file",
            Required: true,
            Destination: &filename,
          },
          &cli.StringFlag{
            Name:        "search",
            Required: true,
            Destination: &search,
          },
    }

  // Define the Main CLI App using the Urfave CLI v2 Syntax
  app := &cli.App{
    // Define the App 
    Name: "goparse",
    Usage: "Parsing Nmap/Burp XML Files Made Easy.",
    Version: "v0.3",
    Compiled: time.Now(),
    Authors: []*cli.Author{
      &cli.Author{
        Name:  "l33tllama",
      },
    },

    // Define the commands
    Commands: []*cli.Command{
      {

        // commands organized by function for Nmap Parsing - will be automatically sorted during command line execution
        // ---------------------------------------------------BURP -------------------------------------------
        Name:        "burp",
        Aliases:     []string{"b"},
        Usage:       "Parsing Burp",
        Subcommands: []*cli.Command{
          {
            Name:  "version",
            Usage: "Get Version of BurpSuite used.",
            Flags: baseFlags,
            Action: func(c *cli.Context) error {
              OpenFile(filename)
              parse.GetBurpVersion(filename)
              return nil
            },
          },
          {
            Name:  "mime-search",
            Usage: "Search for Request/Responses with a specific MIME type.",
            Flags: extraFlags,
            Action: func(c *cli.Context) error {
              OpenFile(filename)
              parse.GetMimeType(filename,search)
              return nil
            },
          },
        },
      },


      // commands organized by function for Nmap Parsing - will be automatically sorted during command line execution
      // --------------------------------------------------- NMAP ---------------------------------------------
      {
        Name:        "nmap",
        Aliases:     []string{"n"},
        Usage:       "Parsing Nmap",


        // FILE INFORMATION --------------------------------------------------------------------------------------

        Subcommands: []*cli.Command{
          {
            Name:  "nmap-cmdline",
            Usage: "Get Args",
            Flags: baseFlags,
            Action: func(c *cli.Context) error {
               // a simple lookup function
                OpenFile(filename)
                parse.GetArguments(filename)
                return nil
            },
          },
          {
            Name:  "version",
            Usage: "Get Version of Nmap used.",
            Flags: baseFlags,
            Action: func(c *cli.Context) error {
               // a simple lookup function
                OpenFile(filename)
                parse.GetVersion(filename)
                return nil
            },
          },
          {
            Name:  "start-time",
            Usage: "Get Nmap Start Time.",
            Flags: baseFlags,
            Action: func(c *cli.Context) error {
               // a simple lookup function
                OpenFile(filename)
                parse.GetStartTime(filename)
                return nil
            },
          },
          {
            Name:  "stop-time",
            Usage: "Get Nmap Stop Time.",
            Flags: baseFlags,
            Action: func(c *cli.Context) error {
               // a simple lookup function
                OpenFile(filename)
                parse.GetVersion(filename)
                return nil
            },
          },


          // HOST INFORMATION ----------------------------------------------------------------------------------
          {
            Name:  "all-hosts",
            Usage: "Retrieves all Hosts that were scanned with Nmap.",
            Flags: baseFlags,
            Action: func(c *cli.Context) error {
               // a simple lookup function
                OpenFile(filename)
                parse.GetAllHosts(filename)
                return nil
            },
          },
          {
            Name:  "up-hosts",
            Usage: "Retrieves all Hosts that were considered 'Up' by Nmap.",
            Flags: baseFlags,
            Action: func(c *cli.Context) error {
               // a simple lookup function
                OpenFile(filename)
                parse.GetUpHosts(filename)
                return nil
            },
          },
          {
            Name:  "host-ports",
            Usage: "Retrieves all the Ports by Nmap.",
            Flags: baseFlags,
            Action: func(c *cli.Context) error {
               // a simple lookup function
                OpenFile(filename)
                parse.GetHostPorts(filename)
                return nil
            },
          },
          {
            Name:  "hosts",
            Usage: "Retrieves all hosts with at least one port open",
            Flags: baseFlags,
            Action: func(c *cli.Context) error {
               // a simple lookup function
                OpenFile(filename)
                parse.GetHostsWithOpenPorts(filename)
                return nil
            },
          },
          {
            Name:  "hosts-to-port",
            Usage: "Extracts a list of all hosts that have the given port open in host (hostname) format.",
            Flags: extraFlags,
            Action: func(c *cli.Context) error {
               // a simple lookup function
                OpenFile(filename)
                // need to check port input here
                port = CheckPort(search)
                parse.GetHostsToPort(filename,port)
                return nil
            },
          },
          {
            Name:  "host-ports-protocol",
            Usage: "Extracts a list of all hosts that have the given port open in host (hostname) format.",
            Flags: baseFlags,
            Action: func(c *cli.Context) error {
               // a simple lookup function
                OpenFile(filename)
                // need to check port input here
                parse.GetHostsPortsProtocol(filename)
                return nil
            },
          },
          // PORT INFORMATION -----------------------------------------------------------
          {
            Name:  "banner",
            Usage: "Retrieves a list of all ports with a specific service that are open. Requires a search flag.",
            Flags: extraFlags,
            Action: func(c *cli.Context) error {
               // a simple lookup function
                OpenFile(filename)
                parse.BannerSearch(filename,search)
                return nil
            },
          },
          {
            Name:  "smb-hosts",
            Usage: "Retrieves a list of all hosts with SMB open.",
            Flags: baseFlags,
            Action: func(c *cli.Context) error {
               // a simple lookup function
                OpenFile(filename)
                parse.GetSMB(filename)
                return nil
            },
          },
          {
            Name:  "smb-messages",
            Usage: "Retrieves a list of all hosts with SMB open AND Message Signing Disabled.",
            Flags: baseFlags,
            Action: func(c *cli.Context) error {
               // a simple lookup function
                OpenFile(filename)
                parse.GetSMBMessage(filename)
                return nil
            },
          },
          {
            Name:  "all-ports",
            Usage: "Retrieves all ports without checking Open/Closed/TCPWrapped with Nmap.",
            Flags: baseFlags,
            Action: func(c *cli.Context) error {
               // a simple lookup function
                OpenFile(filename)
                parse.GetAllPorts(filename)
                return nil
            },
          },
          {
            Name:  "ports",
            Usage: "Retrieves all ports that were found to be Open with Nmap.",
            Flags: baseFlags,
            Action: func(c *cli.Context) error {
               // a simple lookup function
                OpenFile(filename)
                parse.GetUpPorts(filename)
                return nil
            },
          },
          {
            Name:  "service-names",
            Usage: "Retrieves all names of open ports from Nmap scan.",
            Flags: baseFlags,
            Action: func(c *cli.Context) error {
               // a simple lookup function
                OpenFile(filename)
                parse.GetServiceNames(filename)
                return nil
            },
          },
          {
            Name:  "blocked-ports",
            Usage: "Retrieves all ports that were found to be Blocked with Nmap.",
            Flags: baseFlags,
            Action: func(c *cli.Context) error {
               // a simple lookup function
                OpenFile(filename)
                parse.GetBlockedPorts(filename)
                return nil
            },
          },

           // HTTP searches ----------------------------------------------------
           // the following services are detected as HTTP: http, https, http-alt, 
           // https-alt, http-proxy, sip, rtsp, soap, vnc-http, caldav 
           // (potentially incomplete)
          {
            Name:  "http-ports",
            Usage: "Generates a line seperated list of all HTTP(s) ports.",
            Flags: baseFlags,
            Action: func(c *cli.Context) error {
               // a simple lookup function
                OpenFile(filename)
                parse.GetHTTPPorts(filename)
                return nil
            },
          },
          {
            Name:  "http-info",
            Usage: "Generates a line seperated list of all HTTP(s) ports.",
            Flags: baseFlags,
            Action: func(c *cli.Context) error {
               // a simple lookup function
                OpenFile(filename)
                fmt.Println("Will eventually export in format: http://<ip>:port")
                return nil
            },
          },
        },
      },
    },
  }

  // sort the commands to remain consitent across versions
  sort.Sort(cli.FlagsByName(app.Flags))
  sort.Sort(cli.CommandsByName(app.Commands))

  err := app.Run(os.Args)
  if err != nil {
    fmt.Println(err)
  }
}