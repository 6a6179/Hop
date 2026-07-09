package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	"google.golang.org/protobuf/proto"
)

func TestCheckedInBundleContainsOnlyReviewedCategories(t *testing.T) {
	var ips geodata.GeoIPList
	readTestProto(t, filepath.Join("..", "..", "..", "Geodata", "geoip.dat"), &ips)
	if got, want := ipCodes(ips.Entry), []string{"CN", "IR", "PRIVATE"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("GeoIP categories = %v, want %v", got, want)
	}

	var sites geodata.GeoSiteList
	readTestProto(t, filepath.Join("..", "..", "..", "Geodata", "geosite.dat"), &sites)
	if got, want := siteCodes(sites.Entry), []string{"CATEGORY-IR"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("GeoSite categories = %v, want %v", got, want)
	}
}

func TestFiltersAreSortedAndConsumeEveryRequestedCategory(t *testing.T) {
	ipWanted := map[string]bool{"CN": true, "PRIVATE": true}
	ips := filterIPs([]*geodata.GeoIP{
		{Code: "PRIVATE"},
		{Code: "IR"},
		{Code: "CN"},
	}, ipWanted)
	if got, want := ipCodes(ips), []string{"CN", "PRIVATE"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("filtered GeoIP categories = %v, want %v", got, want)
	}
	if len(ipWanted) != 0 {
		t.Fatalf("requested GeoIP categories were not consumed: %v", ipWanted)
	}

	siteWanted := map[string]bool{"CATEGORY-IR": true}
	sites := filterSites([]*geodata.GeoSite{
		{Code: "ZZ"},
		{Code: "CATEGORY-IR"},
	}, siteWanted)
	if got, want := siteCodes(sites), []string{"CATEGORY-IR"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("filtered GeoSite categories = %v, want %v", got, want)
	}
	if len(siteWanted) != 0 {
		t.Fatalf("requested GeoSite categories were not consumed: %v", siteWanted)
	}
}

func readTestProto(t *testing.T, path string, message proto.Message) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := proto.Unmarshal(data, message); err != nil {
		t.Fatal(err)
	}
}

func ipCodes(entries []*geodata.GeoIP) []string {
	result := make([]string, len(entries))
	for index, entry := range entries {
		result[index] = entry.GetCode()
	}
	return result
}

func siteCodes(entries []*geodata.GeoSite) []string {
	result := make([]string, len(entries))
	for index, entry := range entries {
		result[index] = entry.GetCode()
	}
	return result
}
