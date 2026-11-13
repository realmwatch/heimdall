// SPDX-License-Identifier: AGPL-3.0-or-later

package leftovers

import (
	"slices"
	"strings"
	"testing"
)

var (
	focal = Release{"ubuntu", "20.04", "focal"}
	jammy = Release{"ubuntu", "22.04", "jammy"}
)

func TestFromVersion(t *testing.T) {
	for v, want := range map[string]string{
		"0.6.1-2ubuntu0.20.04.3":                "focal",
		"3.8.10-0ubuntu1~20.04.18":              "focal",
		"17.5-1.pgdg20.04+1":                    "focal",
		"1.7.3-1+ubuntu20.04.1+deb.sury.org+2":  "focal",
		"6:8.0.6-1rl1~focal1":                   "focal",
		"5:24.0.7-1~ubuntu.22.04~jammy":         "jammy",
		"2.2.6-1+deb11u1build0.22.04.1":         "jammy",
		"1.0-1ubuntu0.20.04.1~18.04.1":          "bionic", // a focal update backported to bionic
		"1.1.1f-1ubuntu2.24+esm6":               "",
		"3.0.2-0ubuntu1.18":                     "",
		"2.4.49+dfsg-2ubuntu1.10":               "",
		"1:2.20.04-1":                           "",
		"16.20.2-deb-1nodesource1":              "",
		"1.2+discord1":                          "",
		"0.9~21.13-1":                           "", // not a release
		"6.3-2":                                 "",
		"7.4.33-1+ubuntu22.04.1+deb.sury.org+1": "jammy",
	} {
		r, ok := FromVersion("ubuntu", v)
		if ok != (want != "") || r.Codename != want {
			t.Errorf("%q: got %v %v, want %q", v, r, ok, want)
		}
	}
	for v, want := range map[string]string{
		"1.1.1n-0+deb11u5":  "bullseye",
		"15.4-1.pgdg110+1":  "bullseye",
		"2.0-1~bpo12+1":     "bookworm",
		"8.2.1-1+debian11~": "bullseye",
		"3.0.11-1~deb12u2":  "bookworm",
		"1.2-3":             "",
	} {
		r, ok := FromVersion("debian", v)
		if ok != (want != "") || r.Codename != want {
			t.Errorf("debian %q: got %v %v, want %q", v, r, ok, want)
		}
	}
}

func TestSuites(t *testing.T) {
	bookworm, _ := ByCodename("bookworm")
	for _, c := range []struct {
		suite   string
		cur     Release
		want    string
		current string
	}{
		{"focal-pgdg", jammy, "focal", "jammy-pgdg"},
		{"focal-infra-security", jammy, "focal", "jammy-infra-security"},
		{"focal", jammy, "focal", "jammy"},
		{"bionic-pgdg", jammy, "bionic", "jammy-pgdg"},
		{"jammy-updates", jammy, "jammy", "jammy-updates"},
		{"oldstable", bookworm, "bullseye", "stable"},
		{"stable", bookworm, "", ""},
		{"nodistro", jammy, "", ""},
		{"bullseye", jammy, "", ""}, // another distro's
	} {
		r, ok := FromSuite(c.suite, c.cur)
		if ok != (c.want != "") || r.Codename != c.want {
			t.Errorf("%s: %v %v", c.suite, r, ok)
			continue
		}
		if ok && suiteFor(c.suite, r, c.cur) != c.current {
			t.Errorf("%s: for the current release %q", c.suite, suiteFor(c.suite, r, c.cur))
		}
	}
	if !focal.Before(jammy) || jammy.Before(focal) || focal.Before(focal) {
		t.Error("Before")
	}
	if r, ok := FromOSV("Ubuntu:22.04"); !ok || r != jammy || r.OSV() != "Ubuntu:22.04" || r.String() != "Ubuntu 22.04 (jammy)" {
		t.Errorf("FromOSV %v", r)
	}
}

// web01 is a server upgraded in place from 20.04 to 22.04.
func web01() ([]Package, string) {
	pkgs := []Package{
		{"libssl3", "3.0.2-0ubuntu1.18", "openssl", "3.0.2-0ubuntu1.18"},
		{"openssl", "3.0.2-0ubuntu1.18", "openssl", "3.0.2-0ubuntu1.18"},
		{"libssl1.1", "1.1.1f-1ubuntu2.24+esm6", "openssl", "1.1.1f-1ubuntu2.24+esm6"},
		{"libwebp7", "1.2.2-2ubuntu0.22.04.2", "libwebp", "1.2.2-2ubuntu0.22.04.2"},
		{"libwebp6", "0.6.1-2ubuntu0.20.04.3", "libwebp", "0.6.1-2ubuntu0.20.04.3"},
		{"libldap-2.5-0", "2.5.16+dfsg-0ubuntu0.22.04.2", "openldap", "2.5.16+dfsg-0ubuntu0.22.04.2"},
		{"libldap-2.4-2", "2.4.49+dfsg-2ubuntu1.10", "openldap", "2.4.49+dfsg-2ubuntu1.10"},
		{"libperl5.30", "5.30.0-9ubuntu0.5", "perl", "5.30.0-9ubuntu0.5"},
		{"perl", "5.34.0-3ubuntu1.3", "perl", "5.34.0-3ubuntu1.3"},
		{"python3.8", "3.8.10-0ubuntu1~20.04.18", "python3.8", "3.8.10-0ubuntu1~20.04.18"},
		{"libpq5", "17.5-1.pgdg20.04+1", "postgresql-17", "17.5-1.pgdg20.04+1"},
		{"libzip4", "1.7.3-1+ubuntu20.04.1+deb.sury.org+2", "libzip", "1.7.3-1+ubuntu20.04.1+deb.sury.org+2"},
		{"redis-tools", "6:8.0.6-1rl1~focal1", "redis", "6:8.0.6-1rl1~focal1"},
		{"curl", "7.81.0-1ubuntu1.20", "curl", "7.81.0-1ubuntu1.20"},
		{"linux-image-5.4.0-200-generic", "5.4.0-200.220", "linux-signed", "5.4.0-200.220"},
		{"vendor-agent", "2.1.0", "vendor-agent", "2.1.0"},
	}
	header := "v1 cn=jammy maps=40/120;u=sources.list.distUpgrade;" +
		"p=812|php8.3-fpm.service|php-fpm8.3|libssl.so.1.1|libssl1.1;" +
		"p=813|php8.3-fpm.service|php-fpm8.3|libzip.so.4|libzip4;" +
		"p=900||bash|libcurl.so.4|curl;" +
		"s=sources.list.d/pgdg.list|http://apt.postgresql.org/pub/repos/apt|focal-pgdg|main;" +
		"s=sources.list.d/pgdg.list|http://apt.postgresql.org/pub/repos/apt|bionic-pgdg|main;" +
		"s=sources.list.d/ondrej-php.list|https://ppa.launchpadcontent.net/ondrej/php/ubuntu|focal|main;" +
		"s=sources.list.d/ondrej-php.list|https://ppa.launchpadcontent.net/ondrej/php/ubuntu|jammy|main;" +
		"s=sources.list|http://archive.ubuntu.com/ubuntu|jammy-updates|main,universe;" +
		"o=libssl1.1|1.1.1f-1ubuntu2.24+esm6;o=libwebp6|0.6.1-2ubuntu0.20.04.3;o=libldap-2.4-2|2.4.49+dfsg-2ubuntu1.10;" +
		"o=libperl5.30|5.30.0-9ubuntu0.5;o=python3.8|3.8.10-0ubuntu1~20.04.18;o=vendor-agent|2.1.0;" +
		"o=linux-image-5.4.0-200-generic|5.4.0-200.220;" +
		"b=libpq5|17.5-1.pgdg20.04+1|focal-pgdg;b=libzip4|1.7.3-1+ubuntu20.04.1+deb.sury.org+2|focal;" +
		"b=redis-tools|6:8.0.6-1rl1~focal1|focal;" +
		"bogus;p=1|x|y|lib\"bad|libssl1.1;s=half|cut"
	return pkgs, header
}

func TestAnalyzeWeb01(t *testing.T) {
	pkgs, header := web01()
	st, err := Parse(header)
	if err != nil {
		t.Fatal(err)
	}
	if st.Codename != "jammy" || st.MapsRead != 40 || len(st.Uses) != 3 || len(st.Sources) != 5 {
		t.Fatalf("parsed %+v", st)
	}
	a := Analyze(jammy, pkgs, &st)
	for name, want := range map[string]string{
		"libssl1.1": "focal", "libwebp6": "focal", "libldap-2.4-2": "focal", "libperl5.30": "focal",
		"python3.8": "focal", "libpq5": "focal", "libzip4": "focal", "redis-tools": "focal",
		"libssl3": "", "openssl": "", "curl": "", "vendor-agent": "", "linux-image-5.4.0-200-generic": "",
	} {
		if got := a.BuiltFor[name].Codename; got != want {
			t.Errorf("%s built for %q, want %q", name, got, want)
		}
	}
	if !a.Obsolete["vendor-agent"] || !a.Leftover("vendor-agent") || a.Leftover("curl") || a.Leftover("libssl3") {
		t.Error("an obsolete package can't be upgraded, whatever it's built for")
	}
	f := a.Finding
	if f == nil {
		t.Fatal("no finding")
	}
	if f.Kind != "release_leftovers" || f.Severity != "medium" || f.UsageScan != "partial" || f.Previous != "Ubuntu 20.04 (focal)" {
		t.Errorf("finding %+v", f)
	}
	var stale []string
	for _, s := range f.Sources {
		stale = append(stale, s.Suite+">"+s.Current)
	}
	if !slices.Equal(stale, []string{"focal-pgdg>jammy-pgdg", "bionic-pgdg>jammy-pgdg", "focal>jammy"}) {
		t.Errorf("stale sources %v", stale)
	}
	var obs, old []string
	for _, l := range f.Obsolete {
		obs = append(obs, l.Name+"@"+l.BuiltFor)
	}
	for _, l := range f.OldBuilds {
		old = append(old, l.Name+"@"+strings.Join(l.Offered, ","))
	}
	if !slices.Equal(obs, []string{"libssl1.1@Ubuntu 20.04 (focal)", "libwebp6@Ubuntu 20.04 (focal)",
		"libldap-2.4-2@Ubuntu 20.04 (focal)", "libperl5.30@Ubuntu 20.04 (focal)", "python3.8@Ubuntu 20.04 (focal)", "vendor-agent@"}) {
		t.Errorf("obsolete %v (no kernels; a hand-installed .deb has no release)", obs)
	}
	if !slices.Equal(old, []string{"libpq5@focal-pgdg", "libzip4@focal", "redis-tools@focal"}) {
		t.Errorf("old builds %v", old)
	}
	if len(f.UsedBy) != 2 || f.UsedBy[0].Unit != "php8.3-fpm.service" || f.UsedBy[1].Package != "libzip4" {
		t.Errorf("used by %+v (curl isn't a leftover)", f.UsedBy)
	}
	if len(f.Remediation) != 4 || !strings.HasPrefix(f.Remediation[0], "Retarget") || !strings.HasPrefix(f.Remediation[3], "Remove") {
		t.Errorf("remediation %q", f.Remediation)
	}
}

func TestAnalyzeWithoutCollectorState(t *testing.T) {
	pkgs, _ := web01()
	pkgs = append(pkgs,
		// jammy-updates really ships this focal-named version
		Package{"libmbim-glib4", "1.28.0-1~ubuntu20.04.2", "libmbim", "1.28.0-1~ubuntu20.04.2"},
		// a jammy build of an older fwupd, beside the current one
		Package{"libfwupd2", "1.7.9-1~22.04.3", "fwupd", "1.7.9-1~22.04.3"},
		Package{"fwupd", "2.0.20-1ubuntu2~22.04.2", "fwupd", "2.0.20-1ubuntu2~22.04.2"})
	a := Analyze(jammy, pkgs, nil)
	// The version alone: third-party builders' markers count on their own;
	// the Ubuntu archive's only for a twin of a newer source, as does the
	// release upgraded from for a twin with no marker. A marker naming the
	// current release always means current.
	for name, want := range map[string]string{
		"libwebp6": "focal", "libpq5": "focal", "libzip4": "focal", "redis-tools": "focal",
		"libssl1.1": "focal", "libldap-2.4-2": "focal", "libperl5.30": "focal", "libssl3": "", "vendor-agent": "",
		"python3.8": "", "libmbim-glib4": "", "libfwupd2": "", "fwupd": "",
	} {
		if got := a.BuiltFor[name].Codename; got != want {
			t.Errorf("%s built for %q, want %q", name, got, want)
		}
	}
	if a.Finding == nil || a.Finding.UsageScan != "not_reported" || a.Finding.Severity != "low" || len(a.Finding.Sources) != 0 {
		t.Errorf("finding %+v", a.Finding)
	}
}

func TestAnalyzeCleanHost(t *testing.T) {
	pkgs := []Package{
		{"libssl3", "3.0.2-0ubuntu1.18", "openssl", "3.0.2-0ubuntu1.18"},
		{"openssl", "3.0.2-0ubuntu1.15", "openssl", "3.0.2-0ubuntu1.15"}, // held back: same upstream
		{"vendor-agent", "2.1.0", "vendor-agent", "2.1.0"},
	}
	st, err := Parse("v1 cn=jammy maps=0/0;s=sources.list|http://archive.ubuntu.com/ubuntu|jammy|main;o=vendor-agent|2.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if a := Analyze(jammy, pkgs, &st); a.Finding != nil || len(a.BuiltFor) != 0 || !a.Obsolete["vendor-agent"] {
		t.Errorf("a .deb installed by hand isn't a release leftover: %+v", a)
	}
	if a := Analyze(jammy, pkgs, nil); a.Finding != nil || len(a.BuiltFor) != 0 {
		t.Errorf("no collector state: %+v", a)
	}
}

func TestParseRejects(t *testing.T) {
	for _, v := range []string{"", "v2 cn=jammy maps=1/2", "v1 cn=Jammy maps=1/2", "v1 cn=jammy maps=3/2", "v1 cn=jammy", strings.Repeat("x", MaxHeader+1)} {
		if _, err := Parse(v); err == nil {
			t.Errorf("%q parsed", v)
		}
	}
}
