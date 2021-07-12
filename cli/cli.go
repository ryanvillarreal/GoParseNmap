package cli

import(
    // native imports
    "fmt"
    "net/http"
	"os"
    "time"
    "sort"

    // external imports
    "github.com/urfave/cli/v2"
    "github.com/ryanvillarreal/goparse/parse"
)


// define the variables first.
var(
	filename string
    unfinished bool
    search string
    //formatType string
)

func Testing(){
	fmt.Println("hello, world")
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


func CommandLine() {
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

  // define the main app
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
        Name:        "burp",
        Aliases:     []string{"n"},
        Usage:       "Parsing Burp",
        Subcommands: []*cli.Command{
          {
            Name:  "BurpStuff",
            Usage: "add a new template",
            Flags: baseFlags,
            Action: func(c *cli.Context) error {
              fmt.Println("new task template: ", c.Args().First())
              return nil
            },
          },
          {
            Name:  "MoarBurpStuff",
            Usage: "remove an existing template",
            Action: func(c *cli.Context) error {
              fmt.Println("removed task template: ", c.Args().First())
              return nil
            },
          },
        },
      },
      // commands organized by function for Nmap Parsing - will be automatically sorted during command line execution
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
          // PORT INFORMATION -----------------------------------------------------------
          {
            Name:  "banner",
            Usage: "Retrieves a list of all ports with a specific service taht are open. Requires a search flag.",
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
            Name:  "blocked-ports",
            Usage: "Retrieves all ports that were found to be Blocked with Nmap.",
            Flags: baseFlags,
            Action: func(c *cli.Context) error {
               // a simple lookup function
                OpenFile(filename)
                parse.GetUpPorts(filename)
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
                fmt.Println("Will eventually export in format: http://<ip>:port")
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