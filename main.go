package main

import (
	"fmt"
	"image/color"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/domainr/whois"
	"github.com/go-ping/ping"
	"github.com/mdlayher/wol"
)

const (
	windowHeight = 200
	windowWidth  = 280
)

type customLayout struct {
	width, height float32
}

func (c *customLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	if len(objects) > 0 {
		objects[0].Resize(fyne.NewSize(c.width, c.height))
	}
}

func (c *customLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	return fyne.NewSize(c.width, c.height)
}

var Scanner Portscanner

func main() {
	// Greetings in console
	Scanner.Greet()

	a := app.NewWithID("com.lennart.portscanv3")
	a.SetIcon(resourceIconPng)
	w := a.NewWindow("Portscanner v3.5")
	w.Resize(fyne.NewSize(windowWidth, windowHeight))
	w.CenterOnScreen()
	w.SetFixedSize(true)

	// Labels
	targetLabel := widget.NewLabel("      ⭐ target:          ")
	targetLabel.Alignment = fyne.TextAlignCenter
	portsLabel := widget.NewLabel("⭐ ports:")
	portsLabel.Alignment = fyne.TextAlignCenter
	progressLabel := widget.NewLabel("progress:")
	progressLabel.Alignment = fyne.TextAlignCenter
	portsOpenLabel := widget.NewLabel("")
	portsOpenLabel.Alignment = fyne.TextAlignCenter
	portsOpenLabel.TextStyle.Italic = true
	portsOpenLabel.TextStyle.Bold = true
	arrowLabel := widget.NewLabel("»»")
	arrowLabel.Alignment = fyne.TextAlignCenter

	// Entrys
	targetEntry := widget.NewEntry()
	targetEntry.TextStyle.Bold = true
	targetEntry.Text = "localhost"

	targetContainer := container.New(&customLayout{width: 120, height: 40}, targetEntry)

	portsStartEntry := widget.NewEntry()
	portsStartEntry.Text = "1"
	portsEndEntry := widget.NewEntry()
	portsEndEntry.Text = "1000"
	portsEndContainer := container.New(&customLayout{width: 60, height: 40}, portsEndEntry)

	// Progress bar
	progressBar := widget.NewProgressBar()

	// Button
	scanButton := widget.NewButtonWithIcon("scan !", theme.LoginIcon(), func() {
		go func() {
			Scanner.Reset()
			portsOpenLabel.SetText("")
			Scanner.startPort, _ = strconv.Atoi(portsStartEntry.Text)
			Scanner.endPort, _ = strconv.Atoi(portsEndEntry.Text)
			Scanner.scanningPort = Scanner.startPort
			Scanner.Host = targetEntry.Text
			Scanner.totalPorts = Scanner.endPort - Scanner.startPort + 1
			Scanner.progress = 0.0

			// Create a semaphore channel to limit the number of concurrent goroutines
			sem := make(chan struct{}, 100)
			var wg sync.WaitGroup

			for Scanner.scanningPort <= Scanner.endPort {
				currentPort := Scanner.scanningPort
				Scanner.scanningPort++

				sem <- struct{}{}
				wg.Add(1)

				go func(port int) {
					defer func() {
						<-sem
						wg.Done()
					}()

					isOpen := Scanner.ScanPort(port)
					Scanner.Pprogress() // Debug-Ausgabe

					if isOpen {
						Scanner.mutex.Lock()
						Scanner.portso = append(Scanner.portso, port)
						Scanner.ports_open++
						open := fmt.Sprintf("%d port(s) open: %v", Scanner.ports_open, Scanner.portso)
						portsOpenLabel.SetText(open)
						Scanner.mutex.Unlock()
					}

					Scanner.mutex.Lock()
					Scanner.portsScanned++
					Scanner.progress = float64(Scanner.portsScanned) / float64(Scanner.totalPorts)
					progressBar.SetValue(Scanner.progress)
					Scanner.mutex.Unlock()

				}(currentPort)

			}

			wg.Wait()
		}()
	})

	// Checkbox
	checkAll := widget.NewCheck("all ports !", func(value bool) {
		if value {
			portsStartEntry.Disable()
			portsStartEntry.SetText("1")
			portsEndEntry.Disable()
			portsEndEntry.SetText("65535")
		} else {
			portsStartEntry.Enable()
			portsEndEntry.Enable()
		}
	})

	// Layout
	layoutHBox1 := layout.NewHBoxLayout()
	layoutHBox2 := layout.NewHBoxLayout()
	layoutVBox := layout.NewVBoxLayout()

	// Content
	contentPortO := container.NewHScroll(portsOpenLabel)
	contentRow1 := container.New(layoutHBox1, targetLabel, portsLabel)
	contentRow2 := container.New(layoutHBox2, targetContainer, portsStartEntry, arrowLabel, portsEndContainer, checkAll)
	contentVBox := container.New(layoutVBox, contentRow1, contentRow2, progressLabel, progressBar, contentPortO, scanButton)

	// WOL labels:
	wolBroadLabel := widget.NewLabel("⭐ broadcast address:port(7 or 9):")
	wolBroadLabel.Alignment = fyne.TextAlignCenter
	wolMacLabel := widget.NewLabel("⭐ mac address:")
	wolMacLabel.Alignment = fyne.TextAlignCenter
	wolSendLabel := widget.NewLabel("")
	wolSendLabel.Alignment = fyne.TextAlignCenter
	wolSendLabel.TextStyle.Italic = true
	wolSendLabel.TextStyle.Bold = true

	// WOL Entrys
	wolBroadEntry := widget.NewEntry()
	wolBroadEntry.Text = "10.0.0.255:9"
	wolMacEntry := widget.NewEntry()
	wolMacEntry.Text = "xx:xx:xx:xx:xx:xx"

	// WOL Button
	wolButton := widget.NewButtonWithIcon("send !", theme.LoginIcon(), func() {
		go func() {
			wolError := wakeOnLan(wolBroadEntry.Text, wolMacEntry.Text)
			if wolError != nil {
				wolSendLabel.SetText(wolError.Error())
			} else {
				wolSendLabel.SetText("WOL packet sent !")
			}
		}()
	})

	// WOL Layout
	layoutVBoxWOL := layout.NewVBoxLayout()

	// WOL Content
	contentWol := container.New(layoutVBoxWOL, wolBroadLabel, wolBroadEntry, wolMacLabel, wolMacEntry, wolSendLabel, wolButton)

	// PING Labels
	pingHostLabel := widget.NewLabel("                ⭐ host:")
	pingHostLabel.Alignment = fyne.TextAlignCenter
	pingCountLabel := widget.NewLabel("⭐ count:")
	pingCountLabel.Alignment = fyne.TextAlignCenter
	pingTimeoutLabel := widget.NewLabel("⭐ timeout:")
	pingTimeoutLabel.Alignment = fyne.TextAlignCenter
	pingPsLabel := widget.NewLabel("packets sent: 0")
	pingPsLabel.Alignment = fyne.TextAlignCenter
	pingPsLabel.TextStyle.Italic = true
	pingPsLabel.TextStyle.Bold = true
	pingPlLabel := widget.NewLabel("packets lost: 0")
	pingPlLabel.Alignment = fyne.TextAlignCenter
	pingPlLabel.TextStyle.Italic = true
	pingPlLabel.TextStyle.Bold = true
	pingArLabel := widget.NewLabel("average rtt: 0")
	pingArLabel.Alignment = fyne.TextAlignCenter
	pingArLabel.TextStyle.Italic = true
	pingArLabel.TextStyle.Bold = true
	// Empty spacer label for centering HBox2
	pingSpLabel := widget.NewLabel("               ")

	// PING Entrys
	pingHostEntry := widget.NewEntry()
	pingHostEntry.Text = "localhost"
	pingCountEntry := widget.NewEntry()
	pingCountEntry.Text = "5"
	pingCountEntry.Disable()
	pingTimeoutEntry := widget.NewEntry()
	pingTimeoutEntry.Text = "5"
	pingTimeoutEntry.Disable()

	// PING pingHostEntry container
	pingHostContainer := container.New(&customLayout{width: 120, height: 40}, pingHostEntry)

	// PING Button
	pingButton := widget.NewButtonWithIcon("ping !", theme.LoginIcon(), func() {
		go func() {
			count, err := strconv.Atoi(pingCountEntry.Text)
			if err != nil {
				pingArLabel.SetText(err.Error())
			}

			timeout, err := strconv.Atoi(pingTimeoutEntry.Text)
			if err != nil {
				pingArLabel.SetText(err.Error())
			}

			ps, pl, ar, err := pingHost(pingHostEntry.Text, count, timeout)
			if err != nil {
				pingArLabel.SetText(err.Error())
			} else {
				pingPsLabel.SetText(fmt.Sprintf("packets sent: %d", ps))
				pingPlLabel.SetText(fmt.Sprintf("packets lost: %.2f percent", pl))
				pingArLabel.SetText(fmt.Sprintf("average rtt: %.2f milliseconds", ar*1000))
			}
		}()
	})

	// PING Layout
	layoutHBoxping1 := layout.NewHBoxLayout()
	layoutHBoxping2 := layout.NewHBoxLayout()
	layoutVBoxping := layout.NewVBoxLayout()

	// PING Content
	contentPingRow1 := container.New(layoutHBoxping1, pingHostLabel, pingCountLabel, pingTimeoutLabel)
	contentPingRow2 := container.New(layoutHBoxping2, pingSpLabel, pingHostContainer, pingCountEntry, pingTimeoutEntry)
	contentPingVBox := container.New(layoutVBoxping, contentPingRow1, contentPingRow2, pingPsLabel, pingPlLabel, pingArLabel, pingButton)

	// WHOIS Labels
	whoisHostLabel := widget.NewLabel("                   ⭐ host:")
	whoisResLabel := widget.NewLabel("")
	whoisResScroll := container.NewScroll(whoisResLabel)
	whoisResScroll.SetMinSize(fyne.NewSize(200, 150))

	// WHOIS Entrys
	whoisHostEntry := widget.NewEntry()
	whoisHostEntry.Text = "github.com"

	whoisHostEntryContainer := container.New(&customLayout{width: 120, height: 40}, whoisHostEntry)

	// WHOIS Button
	whoisButton := widget.NewButtonWithIcon("go !", theme.LoginIcon(), func() {
		go func() {
			whoisResLabel.SetText(startWhois(whoisHostEntry.Text))
		}()
	})

	// WHOIS Layout
	layoutHBoxWhois := layout.NewHBoxLayout()
	layoutVBoxWhois := layout.NewVBoxLayout()

	// WHOIS Content
	contentWhoisRow1 := container.New(layoutHBoxWhois, whoisHostLabel, whoisHostEntryContainer)
	contentWhoisVBox := container.New(layoutVBoxWhois, contentWhoisRow1, whoisResScroll, whoisButton)

	// Add AppTabs Layout
	tabs := container.NewAppTabs(
		container.NewTabItem("SCAN", contentVBox),
		container.NewTabItem("WOL", contentWol),
		container.NewTabItem("PING", contentPingVBox),
		container.NewTabItem("WHOIS", contentWhoisVBox),
		container.NewTabItem("ABOUT", about()),
	)

	// Tab location: top
	tabs.SetTabLocation(container.TabLocationTop)

	// Set content
	w.SetContent(tabs)

	// Show window and run
	w.ShowAndRun()

}

func about() fyne.CanvasObject {
	image := canvas.NewImageFromResource(resourceWhitePng)
	image.FillMode = canvas.ImageFillOriginal
	gradient := canvas.NewVerticalGradient(color.White, color.RGBA{0, 0, 200, 255})
	cont := container.NewStack(gradient, image)
	image.Translucency = 0.3

	return cont
}

func wakeOnLan(broad, mac string) error {
	// MAC-Address of target
	addr, err := net.ParseMAC(mac)
	if err != nil {
		log.Printf("failed to parse MAC address: %v", err)
		return err
	}

	client, err := wol.NewClient()
	if err != nil {
		log.Printf("failed to create WOL client: %v", err)
		return err
	}

	// Send the WOL-Packet
	if err := client.Wake(broad, addr); err != nil {
		log.Printf("failed to send WOL packet: %v", err)
		return err
	}

	log.Println("WOL packet sent successfully!")
	return nil
}

// sends a ping to host and returns packets send, lost (percentage), average rtt
func pingHost(host string, count int, timeout int) (int, float64, float64, error) {

	if count < 1 || timeout < 1 {
		return 0, 0, 0, fmt.Errorf("invalid count or timeout")
	}

	pinger, err := ping.NewPinger(host)
	if err != nil {
		return 0, 0, 0, err
	}
	pinger.SetPrivileged(false)
	pinger.Count = count
	pinger.Timeout = time.Duration(timeout) * time.Second
	err = pinger.Run()

	if err != nil {
		return 0, 0, 0, err
	}
	pinger.Stop()
	stats := pinger.Statistics()
	fmt.Println("Packets sent: ", stats.PacketsSent, " (5 is max. due to ICMP restrictions)")
	return stats.PacketsSent, stats.PacketLoss, stats.AvgRtt.Seconds(), nil
}

func startWhois(host string) string {
	request, err := whois.NewRequest(host)
	if err != nil {
		fmt.Printf("Error creating Whois query: %s\n", err)
		return err.Error()
	}

	response, err := whois.DefaultClient.Fetch(request)
	if err != nil {
		fmt.Printf("Error retrieving Whois data: %s\n", err)
		return err.Error()
	}

	return response.String()
}
