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
    app.Version = "0.0.1"

    // We'll be using the same flag for all our commands
    // so we'll define it up here
    myFlags := []cli.Flag{
        cli.StringFlag{
            Name:  "file",
            Required: true,
            Destination: &filename,
        },
    }

    // we create our commands
    app.Commands = []cli.Command{
        {
            Name:  "args",
            Usage: "Retrieves the Arguments used for the Nmap scan.",
            Flags: myFlags,
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
            Flags: myFlags,
            // the action, or code that will be executed when
            Action: func(c *cli.Context) error {

                // Get the XML Nmap Version Number
                OpenFile(filename)
                parse.GetVersion(filename)
                return nil
            },
        },
        {
            Name:  "all-hosts",
            Usage: "Retrieves all Hosts that were scanned with Nmap.",
            Flags: myFlags,
            // the action, or code that will be executed when
            Action: func(c *cli.Context) error {
                // a simple lookup function
                OpenFile(filename)
                parse.GetHosts(filename)
                return nil
            },
        },
        {
            Name:  "all-ports",
            Usage: "Retrieves all ports that were found with Nmap..",
            Flags: myFlags,
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
            Flags: myFlags,
            // the action, or code that will be executed when
            Action: func(c *cli.Context) error {
                // a simple lookup function
                OpenFile(filename)
                parse.GetUpPorts(filename)
                return nil
            },
        },
        {
            Name:  "up-hosts",
            Usage: "Retrieves all Hosts that were considered 'Up' by Nmap.",
            Flags: myFlags,
            // the action, or code that will be executed when
            Action: func(c *cli.Context) error {
                // a simple lookup function
                OpenFile(filename)
                parse.GetUpHosts(filename)
                return nil
            },
        },
        {
            Name:  "starttime",
            Usage: "Retrieves the time the Nmap scan started.",
            Flags: myFlags,
            // the action, or code that will be executed when
            Action: func(c *cli.Context) error {
                // a simple lookup function
                OpenFile(filename)
                parse.GetStartTime(filename)
                return nil
            },
        },
        {
            Name:  "stoptime",
            Usage: "Retrieves the time the Nmap scan stopped.",
            Flags: myFlags,
            // the action, or code that will be executed when
            Action: func(c *cli.Context) error {
                // a simple lookup function
                OpenFile(filename)
                parse.GetStopTime(filename)
                return nil
            },
        },
    }

    // sorting the commands for uniformity between versions
    sort.Sort(cli.CommandsByName(app.Commands))

    // start our application
    err := app.Run(os.Args)
    if err != nil {
        fmt.Println(err)
    }
}

