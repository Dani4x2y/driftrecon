package fingerprint

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/bits"
	"strings"

	"golang.org/x/net/html"

	"github.com/Dani4x2y/driftrecon/internal/model"
)

const (
	// SameStructure is the largest SimHash distance at which two documents
	// are treated as the same page template.
	SameStructure = 6
	// SimilarStructure is the largest distance at which two documents still
	// count as built from the same application.
	SimilarStructure = 12

	// Documents are cut off at these bounds so that a hostile page cannot
	// make the walk arbitrarily expensive. The cut is deterministic. The
	// depth matches what the HTML parser accepts.
	maxDOMDepth = 512
	maxDOMNodes = 50000

	// pathLevels is how many trailing tags make up one SimHash feature.
	pathLevels = 4
)

// Structure is the shape of an HTML document with all content removed.
type Structure struct {
	// Skeleton hashes the element tree exactly. It is empty for a document
	// without elements.
	Skeleton string
	// SimHash places documents with a similar tree close to each other.
	SimHash model.SimHash
}

// DOM reduces a parsed document to its structure. Text, comments and
// attributes are ignored, and a run of sibling subtrees with the same shape
// counts once, so a list keeps its skeleton when it grows or shrinks.
func DOM(doc *html.Node) Structure {
	var w domWalker

	h := sha256.New()
	fmt.Fprintf(h, "driftrecon/skeleton/v%d\n", Version)
	w.children(h, doc, nil, 0)
	if w.nodes == 0 {
		return Structure{}
	}

	features := make(map[string]int)
	for _, path := range w.paths {
		features[path]++
	}
	return Structure{
		Skeleton: hex.EncodeToString(h.Sum(nil)),
		SimHash:  simhash(features),
	}
}

// Distance is the number of bits in which two SimHash values differ.
func Distance(a, b model.SimHash) int {
	return bits.OnesCount64(uint64(a ^ b))
}

type domWalker struct {
	nodes int
	// paths logs the tag path of every element that survives collapsing.
	paths []string
}

// Every entry of a child list is tagged, which keeps a repeat marker from
// being read as the start of a subtree hash.
const (
	markChild  = 1
	markRepeat = 2
)

// children writes the hashes of the element children of n to h, marking a
// run of identical subtrees instead of repeating it.
func (w *domWalker) children(h io.Writer, n *html.Node, trail []string, depth int) {
	var (
		prev     [sha256.Size]byte
		havePrev bool
		repeated bool
	)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type != html.ElementNode {
			continue
		}
		if w.nodes >= maxDOMNodes {
			return
		}
		logged := len(w.paths)
		sum := w.subtree(c, trail, depth)
		if havePrev && sum == prev {
			// A repeated subtree adds nothing to the similarity features
			// either, or a longer list would read as a different page.
			w.paths = w.paths[:logged]
			if !repeated {
				h.Write([]byte{markRepeat})
				repeated = true
			}
			continue
		}
		h.Write([]byte{markChild})
		h.Write(sum[:])
		prev, havePrev, repeated = sum, true, false
	}
}

func (w *domWalker) subtree(n *html.Node, trail []string, depth int) [sha256.Size]byte {
	w.nodes++
	tag := n.Data

	path := append(trail[:len(trail):len(trail)], tag)
	if len(path) > pathLevels {
		path = path[len(path)-pathLevels:]
	}
	w.paths = append(w.paths, strings.Join(path, ">"))

	h := sha256.New()
	io.WriteString(h, tag)
	h.Write([]byte{0})
	// Vector graphics are content rather than page structure: an inline icon
	// would otherwise outweigh the layout around it.
	if tag != "svg" && tag != "math" && depth < maxDOMDepth {
		w.children(h, n, path, depth+1)
	}

	var sum [sha256.Size]byte
	h.Sum(sum[:0])
	return sum
}

// simhash folds weighted features into 64 bits. Every feature votes on each
// bit with its weight, so documents that share most of their weight agree on
// most bits. The weight is the bit length of the count, an integer stand-in
// for log2(1+n): a path that occurs often must not drown out the rest of the
// page, and integer votes add up the same in any order.
func simhash(features map[string]int) model.SimHash {
	var votes [64]int
	for feature, count := range features {
		sum := sha256.Sum256([]byte(feature))
		pattern := binary.BigEndian.Uint64(sum[:8])
		weight := bits.Len(uint(count))
		for i := range votes {
			if pattern&(1<<i) != 0 {
				votes[i] += weight
			} else {
				votes[i] -= weight
			}
		}
	}

	var out uint64
	for i, v := range votes {
		if v > 0 {
			out |= 1 << i
		}
	}
	return model.SimHash(out)
}
