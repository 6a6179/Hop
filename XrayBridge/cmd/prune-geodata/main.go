// Command prune-geodata creates the small, deterministic geodata bundle used by Hop.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"
)

func main() {
	geoIPInput := flag.String("geoip", "", "source geoip.dat")
	geoSiteInput := flag.String("geosite", "", "source geosite.dat")
	outputDirectory := flag.String("out", "", "output directory")
	geoIPCodes := flag.String("geoip-codes", "CN,IR,PRIVATE", "comma-separated GeoIP codes")
	geoSiteCodes := flag.String("geosite-codes", "CATEGORY-IR", "comma-separated GeoSite codes")
	flag.Parse()
	if *geoIPInput == "" || *geoSiteInput == "" || *outputDirectory == "" {
		flag.Usage()
		os.Exit(2)
	}
	must(os.MkdirAll(*outputDirectory, 0o755))

	var ips geodata.GeoIPList
	readProto(*geoIPInput, &ips)
	wantedIPs := codeSet(*geoIPCodes)
	ips.Entry = filterIPs(ips.Entry, wantedIPs)
	ensureEmpty(wantedIPs, "GeoIP")
	writeProto(filepath.Join(*outputDirectory, "geoip.dat"), &ips)

	var sites geodata.GeoSiteList
	readProto(*geoSiteInput, &sites)
	wantedSites := codeSet(*geoSiteCodes)
	sites.Entry = filterSites(sites.Entry, wantedSites)
	ensureEmpty(wantedSites, "GeoSite")
	writeProto(filepath.Join(*outputDirectory, "geosite.dat"), &sites)
}

func codeSet(value string) map[string]bool {
	result := map[string]bool{}
	for _, code := range strings.Split(value, ",") {
		if code = strings.ToUpper(strings.TrimSpace(code)); code != "" {
			result[code] = true
		}
	}
	return result
}

func filterIPs(entries []*geodata.GeoIP, wanted map[string]bool) []*geodata.GeoIP {
	var result []*geodata.GeoIP
	for _, entry := range entries {
		code := strings.ToUpper(entry.GetCode())
		if wanted[code] {
			result = append(result, entry)
			delete(wanted, code)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].GetCode() < result[j].GetCode() })
	return result
}

func filterSites(entries []*geodata.GeoSite, wanted map[string]bool) []*geodata.GeoSite {
	var result []*geodata.GeoSite
	for _, entry := range entries {
		code := strings.ToUpper(entry.GetCode())
		if wanted[code] {
			result = append(result, entry)
			delete(wanted, code)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].GetCode() < result[j].GetCode() })
	return result
}

func ensureEmpty(missing map[string]bool, kind string) {
	if len(missing) == 0 {
		return
	}
	codes := make([]string, 0, len(missing))
	for code := range missing {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	panic(fmt.Sprintf("source lacks %s categories: %s", kind, strings.Join(codes, ", ")))
}

func readProto(path string, message proto.Message) {
	data, err := os.ReadFile(path)
	must(err)
	must(proto.Unmarshal(data, message))
}

func writeProto(path string, message proto.Message) {
	data, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	must(err)
	must(os.WriteFile(path, data, 0o644))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
