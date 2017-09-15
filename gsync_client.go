// This Source Code Form is subject to the terms of the Mozilla Public
// License, version 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package gsync

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"sort"

	"github.com/pkg/errors"
)

type BlockSignatureSlice []BlockSignature

type BlockTable interface {
	Put(c BlockSignature)
	Get(weak uint32) ([]BlockSignature, bool)
	Done()
	Len() int
}

type BlockTableMap struct {
	tbl map[uint32][]BlockSignature
}

type BlockTableSlice struct {
	s  BlockSignatureSlice
	ss [][]BlockSignature
}

func (bt *BlockTableMap) Put(c BlockSignature) {
	bt.tbl[c.Weak] = append(bt.tbl[c.Weak], c)
}

func (bt *BlockTableMap) Get(weak uint32) ([]BlockSignature, bool) {
	bs, ok := bt.tbl[weak]
	return bs, ok
}

func (bt *BlockTableMap) Done() {
}

func (bt *BlockTableMap) Len() int {
	return len(bt.tbl)
}

func (bs BlockSignatureSlice) Len() int {
	return len(bs)
}
func (bs BlockSignatureSlice) Swap(i, j int) {
	bs[i], bs[j] = bs[j], bs[i]
}
func (bs BlockSignatureSlice) Less(i, j int) bool {
	return bs[i].Weak < bs[j].Weak
}

func (bt *BlockTableSlice) Put(c BlockSignature) {
	bt.s = append(bt.s, c)
}

func (bt *BlockTableSlice) Get(weak uint32) ([]BlockSignature, bool) {
	i := sort.Search(len(bt.ss), func(i int) bool { return bt.ss[i][0].Weak >= weak })
	if i < len(bt.ss) && bt.ss[i][0].Weak == weak {
		return bt.ss[i], true
	}
	return nil, false
}

func (bt *BlockTableSlice) Done() {
	sort.Sort(bt.s)
	old := bt.s[0]
	olds := make([]BlockSignature, 1)
	olds[0] = old

	for i := 1; i < len(bt.s); i++ {
		if old.Weak == bt.s[i].Weak {
			olds = append(olds, bt.s[i])
		} else {
			bt.ss = append(bt.ss, olds)
			olds = make([]BlockSignature, 1)
			old = bt.s[i]
			olds[0] = old
		}
	}

	if len(olds) > 0 {
		bt.ss = append(bt.ss, olds)
	}

	//reset
	bt.s = nil
}

// LookUpTable reads up blocks signatures and builds a lookup table for the client to search from when trying to decide
// wether to send or not a block of data.
func LookUpTable(ctx context.Context, bc <-chan BlockSignature) (BlockTable, error) {
	//table := make(map[uint32][]BlockSignature)
	table := &BlockTableMap{
		tbl: make(map[uint32][]BlockSignature),
	}

	for c := range bc {
		select {
		case <-ctx.Done():
			return table, errors.Wrapf(ctx.Err(), "failed building lookup table")
		default:
			break
		}

		if c.Error != nil {
			fmt.Printf("gsync: checksum error: %#v\n", c.Error)
			continue
		}
		//table[c.Weak] = append(table[c.Weak], c)
		table.Put(c)
	}

	table.Done()

	return table, nil
}

// Sync sends tokens or literal bytes to the caller in order to efficiently re-construct a remote file. Whether to send
// tokens or literals is determined by the remote checksums provided by the caller.
// This function does not block and returns immediately. Also, the remote blocks map is accessed without a mutex,
// so this function is expected to be called once the remote blocks map is fully populated.
//
// The caller must make sure the concrete reader instance is not nil or this function will panic.
func Sync(ctx context.Context, r io.ReaderAt, shash hash.Hash, remote BlockTable) (<-chan BlockOperation, error) {
	if r == nil {
		return nil, errors.New("gsync: reader required")
	}

	o := make(chan BlockOperation)

	if shash == nil {
		shash = sha256.New()
	}

	go func() {
		var (
			r1, r2, rhash, old uint32
			offset             int64
			rolling, match     bool
		)

		delta := make([]byte, 0)

		defer func() {
			close(o)
		}()

		for {
			// Allow for cancellation.
			select {
			case <-ctx.Done():
				o <- BlockOperation{
					Error: ctx.Err(),
				}
				return
			default:
				break
			}

			bfp := bufferPool.Get().(*[]byte)
			buffer := *bfp

			n, err := r.ReadAt(buffer, offset)
			if err != nil && err != io.EOF {
				o <- BlockOperation{
					Error: errors.Wrapf(err, "failed reading data block"),
				}
				bufferPool.Put(bfp)

				// return since data corruption in the server is possible and a re-sync is required.
				return
			}

			block := buffer[:n]

			// If there are no block signatures from remote server, send all data blocks
			if remote.Len() == 0 {
				if n > 0 {
					o <- BlockOperation{Data: block}
					offset += int64(n)
				}

				if err == io.EOF {
					bufferPool.Put(bfp)
					return
				}
				continue
			}

			if rolling {
				new := uint32(block[n-1])
				r1, r2, rhash = rollingHash2(uint32(n), r1, r2, old, new)
			} else {
				r1, r2, rhash = rollingHash(block)
			}

			if bs, ok := remote.Get(rhash); ok {
				shash.Reset()
				shash.Write(block)
				s := shash.Sum(nil)

				for _, b := range bs {
					if !bytes.Equal(s, b.Strong) {
						continue
					}

					match = true

					// We need to send deltas before sending an index token.
					if len(delta) > 0 {
						send(ctx, bytes.NewReader(delta), o)
						delta = make([]byte, 0)
					}

					// instructs the server to copy block data at offset b.Index
					// from its own copy of the file.
					o <- BlockOperation{Index: b.Index}
					break
				}
			}

			if match {
				if err == io.EOF {
					bufferPool.Put(bfp)
					break
				}

				rolling, match = false, false
				old, rhash, r1, r2 = 0, 0, 0, 0
				offset += int64(n)
			} else {
				if err == io.EOF {
					// If EOF is reached and not match data found, we add trailing data
					// to delta array.
					delta = append(delta, block...)
					if len(delta) > 0 {
						send(ctx, bytes.NewReader(delta), o)
					}
					bufferPool.Put(bfp)
					break
				}
				rolling = true
				old = uint32(block[0])
				delta = append(delta, block[0])
				offset++
			}

			// Returning this buffer to the pool here gives us 5x more speed
			bufferPool.Put(bfp)
		}
	}()

	return o, nil
}

// send sends all deltas over the channel. Any error is reported back using the
// same channel.
func send(ctx context.Context, r io.Reader, o chan<- BlockOperation) {
	for {
		// Allow for cancellation.
		select {
		case <-ctx.Done():
			o <- BlockOperation{
				Error: ctx.Err(),
			}
			return
		default:
			// break out of the select block and continue reading
			break
		}

		bfp := bufferPool.Get().(*[]byte)
		buffer := *bfp
		defer bufferPool.Put(bfp)

		n, err := r.Read(buffer)
		if err != nil && err != io.EOF {
			o <- BlockOperation{
				Error: errors.Wrapf(err, "failed reading data block"),
			}
			return
		}

		// If we don't guard against 0 bytes reads, an operation with index 0 will be sent
		// and the server will duplicate block 0 at the end of the reconstructed file.
		if n > 0 {
			block := buffer[:n]
			o <- BlockOperation{Data: block}
		}

		if err == io.EOF {
			break
		}
	}
}
