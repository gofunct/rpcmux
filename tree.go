package rpcmux

import (
	"bytes"
	"io"
)

type Tree struct {
	root     *ptNode
	maxDepth int // max depth of the tree.
}

func newTree(bs ...[]byte) *Tree {
	max := 0
	for _, b := range bs {
		if max < len(b) {
			max = len(b)
		}
	}
	return &Tree{
		root:     newNode(bs),
		maxDepth: max + 1,
	}
}

func newTreeString(strs ...string) *Tree {
	b := make([][]byte, len(strs))
	for i, s := range strs {
		b[i] = []byte(s)
	}
	return newTree(b...)
}

func (t *Tree) matchPrefix(r io.Reader) bool {
	buf := make([]byte, t.maxDepth)
	n, _ := io.ReadFull(r, buf)
	return t.root.match(buf[:n], true)
}

func (t *Tree) match(r io.Reader) bool {
	buf := make([]byte, t.maxDepth)
	n, _ := io.ReadFull(r, buf)
	return t.root.match(buf[:n], false)
}

type ptNode struct {
	prefix   []byte
	next     map[byte]*ptNode
	terminal bool
}

func newNode(strs [][]byte) *ptNode {
	if len(strs) == 0 {
		return &ptNode{
			prefix:   []byte{},
			terminal: true,
		}
	}

	if len(strs) == 1 {
		return &ptNode{
			prefix:   strs[0],
			terminal: true,
		}
	}

	p, strs := splitPrefix(strs)
	n := &ptNode{
		prefix: p,
	}

	nexts := make(map[byte][][]byte)
	for _, s := range strs {
		if len(s) == 0 {
			n.terminal = true
			continue
		}
		nexts[s[0]] = append(nexts[s[0]], s[1:])
	}

	n.next = make(map[byte]*ptNode)
	for first, rests := range nexts {
		n.next[first] = newNode(rests)
	}

	return n
}

func splitPrefix(bss [][]byte) (prefix []byte, rest [][]byte) {
	if len(bss) == 0 || len(bss[0]) == 0 {
		return prefix, bss
	}

	if len(bss) == 1 {
		return bss[0], [][]byte{{}}
	}

	for i := 0; ; i++ {
		var cur byte
		eq := true
		for j, b := range bss {
			if len(b) <= i {
				eq = false
				break
			}

			if j == 0 {
				cur = b[i]
				continue
			}

			if cur != b[i] {
				eq = false
				break
			}
		}

		if !eq {
			break
		}

		prefix = append(prefix, cur)
	}

	rest = make([][]byte, 0, len(bss))
	for _, b := range bss {
		rest = append(rest, b[len(prefix):])
	}

	return prefix, rest
}

func (n *ptNode) match(b []byte, prefix bool) bool {
	l := len(n.prefix)
	if l > 0 {
		if l > len(b) {
			l = len(b)
		}
		if !bytes.Equal(b[:l], n.prefix) {
			return false
		}
	}

	if n.terminal && (prefix || len(n.prefix) == len(b)) {
		return true
	}

	if l >= len(b) {
		return false
	}

	nextN, ok := n.next[b[l]]
	if !ok {
		return false
	}

	if l == len(b) {
		b = b[l:l]
	} else {
		b = b[l+1:]
	}
	return nextN.match(b, prefix)
}
