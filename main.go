package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket/layers"
	"github.com/urfave/cli/v2"
)

var (
	ports []uint16 = make([]uint16, 0)
)

type ConnMeta struct {
	RemoteIP         string    `json:"remote_ip"`
	RemotePort       uint16    `json:"remote_port"`
	LocalIP          string    `json:"local_ip"`
	LocalPort        uint16    `json:"local_port"`
	Started          time.Time `json:"started_utc"`
	Finished         time.Time `json:"finished_utc"`
	BytesTransferred uint      `json:"bytes_transferred"`
}

func SplitAddr(a net.Addr) (string, uint16, error) {
	parts := strings.Split(a.String(), ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid address '%s'", a.String())
	}
	ip := parts[0]
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("couldn't parse port: %w", err)
	}

	return ip, uint16(port), nil
}

func HandleConnection(c net.Conn, outdir string) {
	defer c.Close()
	log.Printf("Connection Established. Local: %s Remote: %s", c.LocalAddr(), c.RemoteAddr())

	started := time.Now().UTC()

	// make sure we only hold open the connection for a minute
	deadline := time.Now().Add(time.Minute * 5)
	c.SetDeadline(deadline)

	// create filenames for the metadata and the outdata
	base := fmt.Sprintf("%s_%s_%s", time.Now().UTC().Format(time.RFC3339), c.LocalAddr(), c.RemoteAddr())
	data := fmt.Sprintf("%s_data", base)
	meta := fmt.Sprintf("%s_meta", base)
	fulldata := filepath.Join(outdir, data)
	fullmeta := filepath.Join(outdir, meta)

	// open data file and start writing until conn is closed or deadline exceeds
	df, err := os.Create(fulldata)
	if err != nil {
		log.Println(err)
		return
	}
	defer df.Close()

	buf := make([]byte, 1024)
	recvd := 0
	for {
		// make sure we haven't read too much
		if recvd > (5 * 1024 * 1024) {
			break
		}

		// read from socket
		n, err := c.Read(buf)
		if err != nil {
			break
		}

		// populate out counter
		recvd += n

		// write to data file
		_, err = df.Write(buf[:n])
		if err != nil {
			log.Println(err)
			break
		}
	}

	// now write the metadata file
	mf, err := os.Create(fullmeta)
	if err != nil {
		log.Println(err)
		return
	}
	defer mf.Close()

	ended := time.Now().UTC()
	rIP, rPort, err := SplitAddr(c.RemoteAddr())
	if err != nil {
		log.Println(err)
		return
	}
	lIP, lPort, err := SplitAddr(c.LocalAddr())
	if err != nil {
		log.Println(err)
		return
	}
	cm := &ConnMeta{
		RemoteIP:         rIP,
		RemotePort:       rPort,
		LocalIP:          lIP,
		LocalPort:        lPort,
		Started:          started,
		Finished:         ended,
		BytesTransferred: uint(recvd),
	}

	// write json event out
	j, err := json.MarshalIndent(cm, "", " ")
	if err != nil {
		return
	}
	mf.Write(j)
}

func StartListener(port uint16, outdir string) error {
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("Failed to start new listener on %s: %s", addr, err.Error())
		return err
	}
	log.Println("Started new listener on " + addr)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				continue
			}

			go HandleConnection(conn, outdir)
		}
	}()

	return nil
}

func HandlePacket(p netfilter.NFPacket, outdir string) {
	// make sure we always let the packet through
	defer p.SetVerdict(netfilter.NF_ACCEPT)

	// extract the tcp dest port to see if we have a listener yet
	if tcpLayer := p.Packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		listenerRunning := false
		for _, port := range ports {
			if uint16(tcp.DstPort) == port {
				listenerRunning = true
				break
			}
		}

		if !listenerRunning {
			if err := StartListener(uint16(tcp.DstPort), outdir); err == nil {
				ports = append(ports, uint16(tcp.DstPort))
			}
		}
	}

}

func Entry(c *cli.Context) error {
	// get args
	nfnum := c.Uint("queue")
	outdir := c.String("outdir")

	// make sure outdir exists
	if _, err := os.Stat(outdir); os.IsNotExist(err) {
		os.MkdirAll(outdir, os.ModePerm)
	}

	// open netfilter queue
	nfq, err := netfilter.NewNFQueue(uint16(nfnum), 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		return fmt.Errorf("error opening netfilter queue: %w")
	}
	defer nfq.Close()

	// start processing packets
	log.Println("Waiting for incoming TCP SYN packets")
	for {
		select {
		case p := <-nfq.GetPackets():
			HandlePacket(p, outdir)
		}
	}

	return nil
}

func main() {
	app := &cli.App{
		Name: "tcpaccept",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "outdir",
				Aliases:  []string{"o"},
				Usage:    "path to a directory to store output logs",
				Required: true,
			},
			&cli.UintFlag{
				Name:     "queue",
				Aliases:  []string{"q"},
				Usage:    "NF queue to listen on for TCP SYN packets",
				Required: true,
			},
		},
		Action: Entry,
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}
