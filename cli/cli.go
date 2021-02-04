package cli

import(
    // native imports
    "fmt"
    "net/http"
	"os"
    "sort"

    // external imports
    "github.com/urfave/cli"
    "github.com/ryanvillarreal/GoParseNmap/parse"
)


// define the variables first.
var(
	filename string
    unfinished bool
    search string
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


func CommandLine(){
  app := cli.NewApp()
    app.Name = "GoParseNmap"
    app.Usage = "Parsing Nmap XML Files Made Easy."
    app.Author = "l33tllama"
    app.Version = "0.2"

    // FLAGS -----------------------------------------------------------------------------
    // you can create multiple flags and call them within the Commands


    // baseFlags will be used for extraction only commands
    baseFlags := []cli.Flag{
        cli.StringFlag{
            Name:  "file",
            Required: true,
            Destination: &filename,
        },
    }

    // extraFlags will be used for search function commands
    extraFlags := []cli.Flag{
        cli.StringFlag{
            Name:  "file",
            Required: true,
            Destination: &filename,
        },
        cli.StringFlag{
            Name:  "search",
            Required: true,
            Destination: &search,
        },
    }

    // we create our commands
    app.Commands = []cli.Command{
        // commands organized by function - will be automatically sorted during command line execution
        // FILE INFORMATION --------------------------------------------------------------------------------------
        {
            Name:  "nmap-cmdline",
            Usage: "Retrieves the Arguments used for the Nmap scan.",
            Flags: baseFlags,
            // the action, or code that will be executed when
            Action: func(c *cli.Context) error {
                // a simple lookup function
                OpenFile(filename)
                parse.GetArguments(filename)
                return nil
            },
        },
        {
            Name:  "version",
            Usage: "Retrieves the Version of Nmap used to perform the scan.",
            Flags: baseFlags,
            // the action, or code that will be executed when
            Action: func(c *cli.Context) error {

                // Get the XML Nmap Version Number
                OpenFile(filename)
                parse.GetVersion(filename)
                return nil
            },
        },
        {
            Name:  "start-time",
            Usage: "Retrieves the time the Nmap scan started.",
            Flags: baseFlags,
            // the action, or code that will be executed when
            Action: func(c *cli.Context) error {
                // a simple lookup function
                OpenFile(filename)
                parse.GetStartTime(filename)
                return nil
            },
        },
        {
            Name:  "stop-time",
            Usage: "Retrieves the time the Nmap scan stopped.",
            Flags: baseFlags,
            // the action, or code that will be executed when
            Action: func(c *cli.Context) error {
                // a simple lookup function
                OpenFile(filename)
                parse.GetStopTime(filename)
                return nil
            },
        },

        // HOST INFORMATION ----------------------------------------------------------------------------------
        {
            Name:  "all-hosts",
            Usage: "Retrieves all Hosts that were scanned with Nmap.",
            Flags: baseFlags,
            // the action, or code that will be executed when
            Action: func(c *cli.Context) error {
                // a simple lookup function
                OpenFile(filename)
                parse.GetHosts(filename)
                return nil
            },
        },
        {
            Name:  "up-hosts",
            Usage: "Retrieves all Hosts that were considered 'Up' by Nmap.",
            Flags: baseFlags,
            // the action, or code that will be executed when
            Action: func(c *cli.Context) error {
                // a simple lookup function
                OpenFile(filename)
                parse.GetUpHosts(filename)
                return nil
            },
        },
        {
            Name:  "host-ports",
            Usage: "Retrieves the time the Nmap scan stopped.",
            Flags: baseFlags,
            // the action, or code that will be executed when
            Action: func(c *cli.Context) error {
                // a simple lookup function
                OpenFile(filename)
                parse.GetHostPorts(filename)
                return nil
            },
        },
        {
            Name:  "hosts",
            Usage: "Retrieves all hosts with at least one port open.",
            Flags: baseFlags,
            // the action, or code that will be executed when
            Action: func(c *cli.Context) error {
                // a simple lookup function
                OpenFile(filename)
                parse.GetHosts(filename)
                return nil
            },
        },
        // PORT INFORMATION -----------------------------------------------------------
        {
            Name:  "banner",
            Usage: "Retrieves a list of all ports with a specific service taht are open. Requires a search flag.",
            UsageText: "banner requires the --search [SEARCH TERM] flag.",
            Flags: extraFlags,
            // the action, or code that will be executed when
            Action: func(c *cli.Context) error {
                // use the search field to grep through the results
                parse.BannerSearch(filename,search)
                return nil
            },
        },
        {
            Name:  "smb-hosts",
            Usage: "Retrieves a list of all hosts with SMB open.",
            UsageText: "banner requires the --search [SEARCH TERM] flag.",
            Flags: baseFlags,
            // the action, or code that will be executed when
            Action: func(c *cli.Context) error {
                // use the search field to grep through the results
                parse.GetSMB(filename)
                return nil
            },
        },
        {
            Name:  "smb-message",
            Usage: "Retrieves a list of all hosts with SMB open AND Message Signing Disabled.",
            UsageText: "banner requires the --search [SEARCH TERM] flag.",
            Flags: baseFlags,
            // the action, or code that will be executed when
            Action: func(c *cli.Context) error {
                // use the search field to grep through the results
                parse.BannerSearch(filename,search)
                return nil
            },
        },
        {
            Name:  "all-ports",
            Usage: "Retrieves all ports that were found with Nmap..",
            Flags: baseFlags,
            // the action, or code that will be executed when
            Action: func(c *cli.Context) error {
                // a simple lookup function
                OpenFile(filename)
                parse.GetAllPorts(filename)
                return nil
            },
        },
        {
            Name:  "up-ports",
            Usage: "Retrieves all ports that were found with Nmap..",
            Flags: baseFlags,
            // the action, or code that will be executed when
            Action: func(c *cli.Context) error {
                // a simple lookup function
                OpenFile(filename)
                parse.GetUpPorts(filename)
                return nil
            },
        },
        {
            Name:  "blocked-ports",
            Usage: "Retrieves all ports that were found with Nmap..",
            Flags: baseFlags,
            // the action, or code that will be executed when
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
            Usage: "Generates a line separated list of all HTTP(s) ports.",
            Flags: baseFlags,
            // the action, or code that will be executed when
            Action: func(c *cli.Context) error {
                // a simple lookup function
                fmt.Println("Will eventually export in format: http://<ip>:port")
                return nil
            },
        },
        {
            Name:  "http-info",
            Usage: "Generates a line separated list of all HTTP(s) ports.",
            Flags: baseFlags,
            // the action, or code that will be executed when
            Action: func(c *cli.Context) error {
                // a simple lookup function
                fmt.Println("Will eventually export ")
                return nil
            },
        },

        // CUSTOM SEARCHES ------------------------------------------
    }

    // sorting the commands for uniformity between versions
    sort.Sort(cli.CommandsByName(app.Commands))

    // start our application
    err := app.Run(os.Args)
    if err != nil {
        fmt.Println(err)
    }
}

