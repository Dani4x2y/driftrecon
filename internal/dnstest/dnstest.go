// Package dnstest runs an in-process DNS server for tests. It answers like a
// recursive resolver: CNAME chains are followed and wildcards synthesised.
package dnstest

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

// Zone is the data a Server answers from. It may be changed while the
// server is running.
type Zone struct {
	mu       sync.RWMutex
	records  map[string][]dns.RR
	rcodes   map[string]int
	truncate map[string]bool
}

// NewZone builds a zone from records in zone file syntax, for example
// "www.example.test. 60 IN A 192.0.2.10".
func NewZone(records ...string) *Zone {
	z := &Zone{
		records:  make(map[string][]dns.RR),
		rcodes:   make(map[string]int),
		truncate: make(map[string]bool),
	}
	for _, r := range records {
		z.Add(r)
	}
	return z
}

// Add inserts a record. It panics on malformed input.
func (z *Zone) Add(record string) {
	rr, err := dns.NewRR(record)
	if err != nil {
		panic("dnstest: " + err.Error())
	}
	name := strings.ToLower(rr.Header().Name)

	z.mu.Lock()
	defer z.mu.Unlock()
	z.records[name] = append(z.records[name], rr)
}

// Remove deletes every record owned by name.
func (z *Zone) Remove(name string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	delete(z.records, key(name))
}

// Fail makes every query for name return rcode.
func (z *Zone) Fail(name string, rcode int) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.rcodes[key(name)] = rcode
}

// TruncateUDP makes UDP queries for name return an empty truncated answer,
// forcing clients to retry over TCP.
func (z *Zone) TruncateUDP(name string) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.truncate[key(name)] = true
}

func key(name string) string {
	return strings.ToLower(dns.Fqdn(name))
}

// ServeDNS implements dns.Handler.
func (z *Zone) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true

	if len(req.Question) != 1 {
		m.Rcode = dns.RcodeFormatError
		w.WriteMsg(m)
		return
	}
	q := req.Question[0]
	name := strings.ToLower(q.Name)

	z.mu.RLock()
	defer z.mu.RUnlock()

	switch rcode, failing := z.rcodes[name]; {
	case failing:
		m.Rcode = rcode
	case z.truncate[name] && w.RemoteAddr().Network() == "udp":
		m.Truncated = true
	default:
		m.Answer, m.Rcode = z.resolve(name, q.Qtype)
	}
	w.WriteMsg(m)
}

func (z *Zone) resolve(name string, qtype uint16) ([]dns.RR, int) {
	var answer []dns.RR
	for range 8 {
		rrs, exists := z.lookup(name)
		if !exists {
			return answer, dns.RcodeNameError
		}

		next := ""
		for _, rr := range rrs {
			switch rr.Header().Rrtype {
			case qtype:
				answer = append(answer, rr)
			case dns.TypeCNAME:
				answer = append(answer, rr)
				next = strings.ToLower(rr.(*dns.CNAME).Target)
			}
		}
		if next == "" {
			return answer, dns.RcodeSuccess
		}
		name = next
	}
	return answer, dns.RcodeServerFailure
}

// lookup returns the records owned by name. When the name does not exist
// they are synthesised from the wildcard at its closest existing ancestor.
func (z *Zone) lookup(name string) ([]dns.RR, bool) {
	if rrs, ok := z.records[name]; ok {
		return rrs, true
	}

	labels := dns.SplitDomainName(name)
	for i := 1; i < len(labels); i++ {
		parent := dns.Fqdn(strings.Join(labels[i:], "."))
		if rrs, ok := z.records["*."+parent]; ok {
			out := make([]dns.RR, len(rrs))
			for j, rr := range rrs {
				out[j] = dns.Copy(rr)
				out[j].Header().Name = name
			}
			return out, true
		}
		if _, ok := z.records[parent]; ok {
			break
		}
	}
	return nil, false
}

// Server is a running DNS server bound to the loopback interface.
type Server struct {
	// Addr is the ip:port the server listens on, for both UDP and TCP.
	Addr string

	queries atomic.Int64
}

// Queries returns how many questions the server has received.
func (s *Server) Queries() int64 {
	return s.queries.Load()
}

// Start serves zone until the test ends.
func Start(t testing.TB, zone *Zone) *Server {
	t.Helper()

	// UDP and TCP have to share a port number, which the kernel only hands
	// out for one of them. Retry until the pair is free.
	var (
		pc  net.PacketConn
		ln  net.Listener
		err error
	)
	for range 10 {
		if pc, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
			t.Fatalf("dnstest: %v", err)
		}
		if ln, err = net.Listen("tcp", pc.LocalAddr().String()); err == nil {
			break
		}
		pc.Close()
	}
	if err != nil {
		t.Fatalf("dnstest: no free port pair: %v", err)
	}

	s := &Server{Addr: pc.LocalAddr().String()}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		s.queries.Add(1)
		zone.ServeDNS(w, req)
	})

	started := make(chan struct{}, 2)
	notify := func() { started <- struct{}{} }
	udp := &dns.Server{PacketConn: pc, Handler: handler, NotifyStartedFunc: notify}
	tcp := &dns.Server{Listener: ln, Handler: handler, NotifyStartedFunc: notify}
	go udp.ActivateAndServe()
	go tcp.ActivateAndServe()
	<-started
	<-started

	t.Cleanup(func() {
		udp.Shutdown()
		tcp.Shutdown()
	})
	return s
}
