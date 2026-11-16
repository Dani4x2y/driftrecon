package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dani4x2y/driftrecon/internal/model"
	"github.com/Dani4x2y/driftrecon/internal/report"
	"github.com/Dani4x2y/driftrecon/internal/scope"
	"github.com/Dani4x2y/driftrecon/internal/storage"
)

func newShowCmd(a *app) *cobra.Command {
	var (
		targetName string
		scanID     int64
	)
	cmd := &cobra.Command{
		Use:   "show <host or service URL>",
		Short: "Show everything a scan recorded about a host",
		Long: `Show what a scan recorded about a host and the services on it, by default
from the latest completed scan. Given the URL of a service, only that
service is shown.`,
		Example: `  driftrecon show www.example.com
  driftrecon show https://www.example.com --scan 12`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			host, service, err := parseAssetRef(args[0])
			if err != nil {
				return err
			}

			_, store, err := a.open(ctx)
			if err != nil {
				return err
			}
			defer store.Close()

			if targetName == "" {
				names, err := store.TargetsWithHost(ctx, host)
				switch {
				case err != nil:
					return err
				case len(names) == 0:
					return fmt.Errorf("%s is not known to any target", host)
				case len(names) > 1:
					return fmt.Errorf("%s belongs to several targets (%s): pick one with --target", host, strings.Join(names, ", "))
				}
				targetName = names[0]
			}
			target, err := store.GetTarget(ctx, targetName)
			if err != nil {
				return err
			}
			scan, err := selectScan(cmd, store, target, scanID)
			if err != nil {
				return err
			}

			snaps, err := store.HostSnapshots(ctx, scan.ID, host)
			if err != nil {
				return err
			}
			if service != "" {
				snaps = slices.DeleteFunc(snaps, func(s storage.AssetSnapshot) bool { return s.Key != service })
			}
			if len(snaps) == 0 {
				return fmt.Errorf("%s is not part of scan #%d of %s", args[0], scan.ID, target.Name)
			}

			var digests []string
			for _, snap := range snaps {
				if snap.CertSHA256 != "" {
					digests = append(digests, snap.CertSHA256)
				}
			}
			certs, err := store.Certificates(ctx, digests...)
			if err != nil {
				return err
			}
			return renderDetails(cmd.OutOrStdout(), target, scan, snaps, certs, a.now())
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&targetName, "target", "", "target the host belongs to (only needed when several track it)")
	flags.Int64Var(&scanID, "scan", 0, "scan to show (default: latest completed scan)")
	return cmd
}

// parseAssetRef reads what the user named: a hostname, or the URL of one
// service. It returns the host and, for a URL, the key of the service.
func parseAssetRef(ref string) (host, service string, err error) {
	if !strings.Contains(ref, "://") {
		host, err = scope.NormalizeHost(ref)
		return host, "", err
	}

	u, err := url.Parse(ref)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "", "", fmt.Errorf("%q is not an http or https URL", ref)
	}
	if host, err = scope.NormalizeHost(u.Hostname()); err != nil {
		return "", "", err
	}
	port := defaultPort(u.Scheme)
	if p := u.Port(); p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil || n == 0 {
			return "", "", fmt.Errorf("%q has an invalid port", ref)
		}
		port = uint16(n)
	}
	return host, model.ServiceKey(u.Scheme, host, port), nil
}

func renderDetails(w io.Writer, target *storage.Target, scan *storage.Scan, snaps []storage.AssetSnapshot, certs map[string]model.Certificate, now time.Time) error {
	_, err := fmt.Fprintf(w, "scan #%d of %s (%s, %s)\n", scan.ID, target.Name, scan.Profile, scan.StartedAt.Format(timeFormat))
	if err != nil {
		return err
	}
	for _, snap := range snaps {
		var section report.Section
		if snap.Kind == model.KindService {
			section, err = serviceSection(snap, certs, now)
		} else {
			section, err = hostSection(snap)
		}
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
		if err := section.Render(w); err != nil {
			return err
		}
	}
	return nil
}

func hostSection(snap storage.AssetSnapshot) (report.Section, error) {
	var obs model.HostObservation
	if err := json.Unmarshal(snap.Data, &obs); err != nil {
		return report.Section{}, fmt.Errorf("asset %s: malformed observation: %w", snap.Key, err)
	}

	s := report.Section{Title: "host " + snap.Host}
	s.Add("state", string(snap.State))
	addHistory(&s, snap)
	s.Add("sources", strings.Join(snap.Sources, ", "))
	if dns := obs.DNS; dns != nil {
		s.Add("dns", dns.Rcode)
		s.Add("addresses", strings.Join(slices.Concat(dns.A, dns.AAAA), ", "))
		s.Add("cname", strings.Join(dns.CNAME, " > "))
		s.Add("nameservers", strings.Join(dns.NS, ", "))
	}
	s.Add("fingerprint", shortHash(snap.FP), layerLine("dns", snap.FPDNS))
	return s, nil
}

func serviceSection(snap storage.AssetSnapshot, certs map[string]model.Certificate, now time.Time) (report.Section, error) {
	obs, err := decodeService(snap)
	if err != nil {
		return report.Section{}, err
	}

	s := report.Section{Title: "service " + displayURL(snap.Key)}
	state := string(snap.State)
	if obs.Error != "" {
		state += " (" + obs.Error + ")"
	}
	s.Add("state", state)
	addHistory(&s, snap)

	var response []string
	for _, hop := range obs.Hops {
		line := strconv.Itoa(hop.Status)
		if hop.Location != "" {
			line += fmt.Sprintf(" > %s (%s)", hop.Location, hop.Relation)
		}
		response = append(response, line)
	}
	s.Add("response", response...)

	if h := obs.Headers; h != nil {
		s.Add("server", h.Values["server"])
		s.Add("headers", strings.Join(h.Names, ", "))

		var values []string
		for _, name := range slices.Sorted(maps.Keys(h.Values)) {
			if name != "server" {
				values = append(values, name+": "+h.Values[name])
			}
		}
		s.Add("values", values...)

		cookies := make([]string, len(h.Cookies))
		for i, c := range h.Cookies {
			cookies[i] = c.Name
			if len(c.Flags) > 0 {
				cookies[i] += " (" + strings.Join(c.Flags, ", ") + ")"
			}
		}
		s.Add("cookies", strings.Join(cookies, ", "))
	}

	if p := obs.Page; p != nil {
		s.Add("title", p.Title)
		s.Add("generator", p.Generator)
		content := p.ContentType
		if p.BodySHA256 != "" {
			content = strings.TrimPrefix(content+", sha256 "+shortHash(p.BodySHA256), ", ")
		}
		if p.Truncated {
			content += " (cut off at the size limit)"
		}
		s.Add("content", content)

		forms := make([]string, len(p.Forms))
		for i, form := range p.Forms {
			fields := make([]string, len(form.Fields))
			for j, f := range form.Fields {
				fields[j] = strings.TrimSpace(f.Type + " " + f.Name)
			}
			forms[i] = strings.TrimSpace(form.Method+" "+form.Action) + ": " + strings.Join(fields, ", ")
		}
		s.Add("forms", forms...)
		s.Add("scripts", scriptSummary(p.Scripts, snap.Host))
	}
	if obs.Favicon != nil {
		s.Add("favicon", fmt.Sprintf("mmh3 %d", *obs.Favicon))
	}

	if t := obs.TLS; t != nil {
		negotiated := []string{t.Version, t.Cipher}
		if t.ALPN != "" {
			negotiated = append(negotiated, "alpn "+t.ALPN)
		}
		s.Add("tls", strings.Join(negotiated, ", "))
		if cert, ok := certs[snap.CertSHA256]; ok {
			s.Add("certificate", certificateLines(cert, now)...)
		}
		s.Add("trust issues", strings.Join(t.Issues, ", "))
	}

	s.Add("volatile", strings.Join(obs.Volatile, ", "))

	layers := []string{
		layerLine("tls", snap.FPTLS),
		layerLine("headers", snap.FPHeaders),
		layerLine("redirect", snap.FPRedirect),
		layerLine("dom", snap.FPDOM),
	}
	if snap.DOMSimHash != nil {
		layers = append(layers, "simhash "+snap.DOMSimHash.String())
	}
	s.Add("fingerprint", append([]string{shortHash(snap.FP)}, layers...)...)
	return s, nil
}

func addHistory(s *report.Section, snap storage.AssetSnapshot) {
	s.Add("first seen", snap.FirstSeenAt.Format(timeFormat))
	s.Add("last seen", snap.LastSeenAt.Format(timeFormat))
}

func layerLine(name, hash string) string {
	if hash == "" {
		return ""
	}
	return name + " " + shortHash(hash)
}

func certificateLines(cert model.Certificate, now time.Time) []string {
	issuer := cert.IssuerCN
	if cert.IssuerOrg != "" && cert.IssuerOrg != cert.IssuerCN {
		issuer = strings.TrimSpace(issuer + " (" + cert.IssuerOrg + ")")
	}
	subject := cert.SubjectCN
	if subject == "" {
		subject = "(no common name)"
	}
	first := subject + ", issued by " + issuer
	if cert.SelfSigned {
		first = subject + ", self-signed"
	}

	lines := []string{
		first,
		fmt.Sprintf("valid %s to %s (%s)", cert.NotBefore.Format(time.DateOnly), cert.NotAfter.Format(time.DateOnly), validity(cert, now)),
	}
	if len(cert.SANs) > 0 {
		lines = append(lines, "names: "+abbreviate(cert.SANs, 6))
	}
	return append(lines, fmt.Sprintf("key %s, sha256 %s", cert.KeyAlg, shortHash(cert.SHA256)))
}

// validity describes where now falls in the lifetime of a certificate.
func validity(cert model.Certificate, now time.Time) string {
	const day = 24 * time.Hour
	switch {
	case now.Before(cert.NotBefore):
		return "not valid yet"
	case now.After(cert.NotAfter):
		return fmt.Sprintf("expired %d days ago", int(now.Sub(cert.NotAfter)/day))
	}
	return fmt.Sprintf("%d days left", int(cert.NotAfter.Sub(now)/day))
}

// scriptSummary counts the scripts a page loads and names the other hosts
// they come from.
func scriptSummary(scripts []string, host string) string {
	if len(scripts) == 0 {
		return ""
	}
	var others []string
	for _, script := range scripts {
		if u, err := url.Parse(script); err == nil && !strings.EqualFold(u.Hostname(), host) {
			others = append(others, strings.ToLower(u.Hostname()))
		}
	}
	slices.Sort(others)
	others = slices.Compact(others)

	summary := strconv.Itoa(len(scripts))
	if len(others) > 0 {
		summary += ", also from " + abbreviate(others, 6)
	}
	return summary
}
