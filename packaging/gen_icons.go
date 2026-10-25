//go:build ignore

// Command gen_icons processes assets/logo.png into a clean 512x512 RGBA PNG,
// generates a multi-resolution Windows assets/icon.ico, and emits COFF PE
// resource objects (cmd/sentinel-net/rsrc_windows_amd64.syso and arm64) so
// go build embeds the application icon and Win32 manifest without external tools.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

func main() {
	raw, err := os.ReadFile("assets/logo.png")
	if err != nil {
		fatalf("read assets/logo.png: %v", err)
	}
	srcImg, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		fatalf("decode assets/logo.png: %v", err)
	}

	cleaned := applyRoundedMask(srcImg)
	img512 := resizeArea(cleaned, 512)

	var buf512 bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&buf512, img512); err != nil {
		fatalf("encode 512 png: %v", err)
	}
	if err := os.WriteFile("assets/logo.png", buf512.Bytes(), 0o644); err != nil {
		fatalf("write assets/logo.png: %v", err)
	}

	sizes := []int{256, 64, 48, 32, 16}
	frames := make([][]byte, 0, len(sizes))
	meta := make([]icoEntryMeta, 0, len(sizes))

	for _, sz := range sizes {
		resized := resizeArea(img512, sz)
		var payload []byte
		if sz == 256 {
			var pb bytes.Buffer
			if err := enc.Encode(&pb, resized); err != nil {
				fatalf("encode 256 png: %v", err)
			}
			payload = pb.Bytes()
		} else {
			payload = encodeDIB32(resized)
		}
		wByte := uint8(sz)
		hByte := uint8(sz)
		if sz >= 256 {
			wByte = 0
			hByte = 0
		}
		frames = append(frames, payload)
		meta = append(meta, icoEntryMeta{
			width:    wByte,
			height:   hByte,
			planes:   1,
			bitCount: 32,
			size:     uint32(len(payload)),
		})
	}

	icoBytes := buildICO(meta, frames)
	if err := os.WriteFile("assets/icon.ico", icoBytes, 0o644); err != nil {
		fatalf("write assets/icon.ico: %v", err)
	}

	manifest := []byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0" processorArchitecture="*" name="SentinelNet.Scanner" type="win32"/>
  <description>Sentinel Net - Defensive Network Exposure Scanner</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
</assembly>`)

	sysoAMD64 := buildCOFFResource(0x8664, 0x0003, meta, frames, manifest)
	sysoARM64 := buildCOFFResource(0xAA64, 0x0002, meta, frames, manifest)
	for _, dir := range []string{"cmd/sentinel-net", "cmd/sentinel-net-gui"} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fatalf("mkdir %s: %v", dir, err)
		}
		if err := os.WriteFile(dir+"/rsrc_windows_amd64.syso", sysoAMD64, 0o644); err != nil {
			fatalf("write %s amd64 syso: %v", dir, err)
		}
		if err := os.WriteFile(dir+"/rsrc_windows_arm64.syso", sysoARM64, 0o644); err != nil {
			fatalf("write %s arm64 syso: %v", dir, err)
		}
	}

	fmt.Printf("Generated assets/logo.png (%d bytes), assets/icon.ico (%d bytes), and Windows .syso resources.\n",
		buf512.Len(), len(icoBytes))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func applyRoundedMask(src image.Image) *image.NRGBA {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	dst := image.NewNRGBA(image.Rect(0, 0, w, h))

	// Rounded-square radius ~ 23.2% of side length cleanly trims white exterior corners.
	radius := float64(w) * 0.232
	aa := math.Max(1.5, float64(w)/512.0)

	for y := 0; y < h; y++ {
		fy := float64(y) + 0.5
		for x := 0; x < w; x++ {
			fx := float64(x) + 0.5
			sd := signedDistRoundedRect(fx, fy, float64(w), float64(h), radius)
			var maskAlpha float64
			if sd <= -aa {
				maskAlpha = 1.0
			} else if sd >= aa {
				maskAlpha = 0.0
			} else {
				maskAlpha = 0.5 - sd/(2.0*aa)
			}

			if maskAlpha <= 0 {
				dst.SetNRGBA(x, y, color.NRGBA{0, 0, 0, 0})
				continue
			}

			r16, g16, b16, a16 := src.At(b.Min.X+x, b.Min.Y+y).RGBA()
			r := float64(r16) / 257.0
			g := float64(g16) / 257.0
			bl := float64(b16) / 257.0
			a := (float64(a16) / 257.0) * maskAlpha

			dst.SetNRGBA(x, y, color.NRGBA{
				R: uint8(math.Round(r)),
				G: uint8(math.Round(g)),
				B: uint8(math.Round(bl)),
				A: uint8(math.Round(a)),
			})
		}
	}
	return dst
}

func signedDistRoundedRect(x, y, w, h, r float64) float64 {
	cx := w * 0.5
	cy := h * 0.5
	qx := math.Abs(x-cx) - (cx - r)
	qy := math.Abs(y-cy) - (cy - r)
	ox := math.Max(qx, 0)
	oy := math.Max(qy, 0)
	outside := math.Hypot(ox, oy)
	inside := math.Min(math.Max(qx, qy), 0)
	return outside + inside - r
}

func resizeArea(src *image.NRGBA, targetSize int) *image.NRGBA {
	sw := src.Bounds().Dx()
	sh := src.Bounds().Dy()
	if sw == targetSize && sh == targetSize {
		return src
	}
	dst := image.NewNRGBA(image.Rect(0, 0, targetSize, targetSize))
	scaleX := float64(sw) / float64(targetSize)
	scaleY := float64(sh) / float64(targetSize)

	for dy := 0; dy < targetSize; dy++ {
		sy0 := float64(dy) * scaleY
		sy1 := float64(dy+1) * scaleY
		iy0 := int(math.Floor(sy0))
		iy1 := int(math.Ceil(sy1))
		if iy1 > sh {
			iy1 = sh
		}
		for dx := 0; dx < targetSize; dx++ {
			sx0 := float64(dx) * scaleX
			sx1 := float64(dx+1) * scaleX
			ix0 := int(math.Floor(sx0))
			ix1 := int(math.Ceil(sx1))
			if ix1 > sw {
				ix1 = sw
			}

			var sumR, sumG, sumB, sumA, sumW float64
			for sy := iy0; sy < iy1; sy++ {
				wy := math.Min(float64(sy+1), sy1) - math.Max(float64(sy), sy0)
				if wy <= 0 {
					continue
				}
				for sx := ix0; sx < ix1; sx++ {
					wx := math.Min(float64(sx+1), sx1) - math.Max(float64(sx), sx0)
					if wx <= 0 {
						continue
					}
					w := wx * wy
					c := src.NRGBAAt(sx, sy)
					af := float64(c.A) / 255.0
					// Premultiplied accumulation prevents dark/bright fringes on alpha edges.
					sumR += float64(c.R) * af * w
					sumG += float64(c.G) * af * w
					sumB += float64(c.B) * af * w
					sumA += af * w
					sumW += w
				}
			}

			if sumW <= 0 || sumA <= 0 {
				dst.SetNRGBA(dx, dy, color.NRGBA{0, 0, 0, 0})
				continue
			}
			outA := sumA / sumW
			outR := (sumR / sumW) / outA
			outG := (sumG / sumW) / outA
			outB := (sumB / sumW) / outA
			dst.SetNRGBA(dx, dy, color.NRGBA{
				R: clampByte(outR),
				G: clampByte(outG),
				B: clampByte(outB),
				A: clampByte(outA * 255.0),
			})
		}
	}
	return dst
}

func clampByte(v float64) uint8 {
	if v <= 0 {
		return 0
	}
	if v >= 255 {
		return 255
	}
	return uint8(math.Round(v))
}

func encodeDIB32(img *image.NRGBA) []byte {
	w := img.Bounds().Dx()
	h := img.Bounds().Dy()
	andRowBytes := ((w + 31) / 32) * 4
	xorBytes := w * h * 4
	andBytes := andRowBytes * h

	buf := make([]byte, 40+xorBytes+andBytes)
	binary.LittleEndian.PutUint32(buf[0:4], 40)           // biSize
	binary.LittleEndian.PutUint32(buf[4:8], uint32(w))    // biWidth
	binary.LittleEndian.PutUint32(buf[8:12], uint32(h*2)) // biHeight (XOR + AND)
	binary.LittleEndian.PutUint16(buf[12:14], 1)          // biPlanes
	binary.LittleEndian.PutUint16(buf[14:16], 32)         // biBitCount
	binary.LittleEndian.PutUint32(buf[20:24], uint32(xorBytes+andBytes))

	xorOff := 40
	andOff := 40 + xorBytes
	for y := 0; y < h; y++ {
		srcY := h - 1 - y // Bottom-up scanlines in DIB
		for x := 0; x < w; x++ {
			c := img.NRGBAAt(x, srcY)
			p := xorOff + (y*w+x)*4
			buf[p+0] = c.B
			buf[p+1] = c.G
			buf[p+2] = c.R
			buf[p+3] = c.A
			if c.A < 16 {
				byteIdx := andOff + y*andRowBytes + (x / 8)
				bitIdx := uint(7 - (x % 8))
				buf[byteIdx] |= 1 << bitIdx
			}
		}
	}
	return buf
}

type icoEntryMeta struct {
	width    uint8
	height   uint8
	planes   uint16
	bitCount uint16
	size     uint32
}

func buildICO(meta []icoEntryMeta, frames [][]byte) []byte {
	var out bytes.Buffer
	_ = binary.Write(&out, binary.LittleEndian, uint16(0))
	_ = binary.Write(&out, binary.LittleEndian, uint16(1))
	_ = binary.Write(&out, binary.LittleEndian, uint16(len(meta)))

	offset := uint32(6 + 16*len(meta))
	for i, m := range meta {
		out.WriteByte(m.width)
		out.WriteByte(m.height)
		out.WriteByte(0)
		out.WriteByte(0)
		_ = binary.Write(&out, binary.LittleEndian, m.planes)
		_ = binary.Write(&out, binary.LittleEndian, m.bitCount)
		_ = binary.Write(&out, binary.LittleEndian, uint32(len(frames[i])))
		_ = binary.Write(&out, binary.LittleEndian, offset)
		offset += uint32(len(frames[i]))
	}
	for _, f := range frames {
		out.Write(f)
	}
	return out.Bytes()
}

func buildGroupIconDir(meta []icoEntryMeta) []byte {
	var out bytes.Buffer
	_ = binary.Write(&out, binary.LittleEndian, uint16(0))
	_ = binary.Write(&out, binary.LittleEndian, uint16(1))
	_ = binary.Write(&out, binary.LittleEndian, uint16(len(meta)))
	for i, m := range meta {
		out.WriteByte(m.width)
		out.WriteByte(m.height)
		out.WriteByte(0)
		out.WriteByte(0)
		_ = binary.Write(&out, binary.LittleEndian, m.planes)
		_ = binary.Write(&out, binary.LittleEndian, m.bitCount)
		_ = binary.Write(&out, binary.LittleEndian, m.size)
		_ = binary.Write(&out, binary.LittleEndian, uint16(i+1)) // RT_ICON 1-based ID
	}
	return out.Bytes()
}

type rsrcLeaf struct {
	typeID uint16
	nameID uint16
	langID uint16
	data   []byte
}

func buildCOFFResource(machine uint16, relocType uint16, meta []icoEntryMeta, frames [][]byte, manifest []byte) []byte {
	// Resource types must appear in ascending numeric order: RT_ICON (3), RT_GROUP_ICON (14), RT_MANIFEST (24).
	leaves := make([]rsrcLeaf, 0, len(frames)+2)
	for i, f := range frames {
		leaves = append(leaves, rsrcLeaf{
			typeID: 3,
			nameID: uint16(i + 1),
			langID: 0x0409,
			data:   f,
		})
	}
	leaves = append(leaves, rsrcLeaf{
		typeID: 14,
		nameID: 1,
		langID: 0x0409,
		data:   buildGroupIconDir(meta),
	})
	leaves = append(leaves, rsrcLeaf{
		typeID: 24,
		nameID: 1,
		langID: 0x0409,
		data:   manifest,
	})

	// Group leaves by typeID preserving ascending order.
	type typeGroup struct {
		typeID uint16
		items  []int
	}
	var groups []typeGroup
	for idx, lf := range leaves {
		if len(groups) == 0 || groups[len(groups)-1].typeID != lf.typeID {
			groups = append(groups, typeGroup{typeID: lf.typeID, items: []int{idx}})
		} else {
			groups[len(groups)-1].items = append(groups[len(groups)-1].items, idx)
		}
	}

	// Calculate directory layout inside .rsrc section:
	// Level 1: 1 root dir (16 bytes) + len(groups)*8 entries
	// Level 2: for each group, 1 dir (16 bytes) + len(group.items)*8 entries
	// Level 3: for each leaf, 1 lang dir (16 bytes) + 1*8 entry
	// Data entries: len(leaves) * 16 bytes
	// Raw payloads: aligned to 8 bytes each
	lvl1Size := 16 + len(groups)*8
	lvl2Offset := lvl1Size
	lvl2Size := 0
	for _, g := range groups {
		lvl2Size += 16 + len(g.items)*8
	}
	lvl3Offset := lvl2Offset + lvl2Size
	lvl3Size := len(leaves) * (16 + 8)
	dataEntriesOffset := lvl3Offset + lvl3Size
	payloadStart := align8(dataEntriesOffset + len(leaves)*16)

	var rsrc bytes.Buffer
	writeDirHeader := func(idCount uint16) {
		_ = binary.Write(&rsrc, binary.LittleEndian, uint32(0)) // Characteristics
		_ = binary.Write(&rsrc, binary.LittleEndian, uint32(0)) // TimeDateStamp
		_ = binary.Write(&rsrc, binary.LittleEndian, uint16(0)) // MajorVersion
		_ = binary.Write(&rsrc, binary.LittleEndian, uint16(0)) // MinorVersion
		_ = binary.Write(&rsrc, binary.LittleEndian, uint16(0)) // NumberOfNamedEntries
		_ = binary.Write(&rsrc, binary.LittleEndian, idCount)   // NumberOfIdEntries
	}
	writeDirEntry := func(id uint16, targetOffset uint32, isSubdir bool) {
		_ = binary.Write(&rsrc, binary.LittleEndian, uint32(id))
		if isSubdir {
			targetOffset |= 0x80000000
		}
		_ = binary.Write(&rsrc, binary.LittleEndian, targetOffset)
	}

	// Emit Level 1
	writeDirHeader(uint16(len(groups)))
	curLvl2 := lvl2Offset
	for _, g := range groups {
		writeDirEntry(g.typeID, uint32(curLvl2), true)
		curLvl2 += 16 + len(g.items)*8
	}

	// Emit Level 2
	curLvl3 := lvl3Offset
	for _, g := range groups {
		writeDirHeader(uint16(len(g.items)))
		for _, leafIdx := range g.items {
			writeDirEntry(leaves[leafIdx].nameID, uint32(curLvl3), true)
			curLvl3 += 24
		}
	}

	// Emit Level 3
	for i, lf := range leaves {
		writeDirHeader(1)
		dataEntryOff := dataEntriesOffset + i*16
		writeDirEntry(lf.langID, uint32(dataEntryOff), false)
	}

	// Compute payload offsets and emit IMAGE_RESOURCE_DATA_ENTRY records
	payloadOffsets := make([]int, len(leaves))
	curPayload := payloadStart
	for i, lf := range leaves {
		payloadOffsets[i] = curPayload
		curPayload = align8(curPayload + len(lf.data))
	}

	relocOffsets := make([]uint32, len(leaves))
	for i, lf := range leaves {
		relocOffsets[i] = uint32(rsrc.Len()) // OffsetToData field is at byte 0 of IMAGE_RESOURCE_DATA_ENTRY
		_ = binary.Write(&rsrc, binary.LittleEndian, uint32(payloadOffsets[i]))
		_ = binary.Write(&rsrc, binary.LittleEndian, uint32(len(lf.data)))
		_ = binary.Write(&rsrc, binary.LittleEndian, uint32(0)) // CodePage
		_ = binary.Write(&rsrc, binary.LittleEndian, uint32(0)) // Reserved
	}

	for rsrc.Len() < payloadStart {
		rsrc.WriteByte(0)
	}
	for _, lf := range leaves {
		rsrc.Write(lf.data)
		for rsrc.Len()%8 != 0 {
			rsrc.WriteByte(0)
		}
	}

	rsrcBytes := rsrc.Bytes()
	relocsOffset := 60 + len(rsrcBytes)
	symTableOffset := relocsOffset + len(relocOffsets)*10

	var coff bytes.Buffer
	// IMAGE_FILE_HEADER (20 bytes)
	_ = binary.Write(&coff, binary.LittleEndian, machine)
	_ = binary.Write(&coff, binary.LittleEndian, uint16(1))              // NumberOfSections
	_ = binary.Write(&coff, binary.LittleEndian, uint32(0))              // TimeDateStamp
	_ = binary.Write(&coff, binary.LittleEndian, uint32(symTableOffset)) // PointerToSymbolTable
	_ = binary.Write(&coff, binary.LittleEndian, uint32(1))              // NumberOfSymbols
	_ = binary.Write(&coff, binary.LittleEndian, uint16(0))              // SizeOfOptionalHeader
	_ = binary.Write(&coff, binary.LittleEndian, uint16(0))              // Characteristics

	// IMAGE_SECTION_HEADER (40 bytes)
	var sectName [8]byte
	copy(sectName[:], ".rsrc")
	coff.Write(sectName[:])
	_ = binary.Write(&coff, binary.LittleEndian, uint32(0))                 // VirtualSize
	_ = binary.Write(&coff, binary.LittleEndian, uint32(0))                 // VirtualAddress
	_ = binary.Write(&coff, binary.LittleEndian, uint32(len(rsrcBytes)))    // SizeOfRawData
	_ = binary.Write(&coff, binary.LittleEndian, uint32(60))                // PointerToRawData
	_ = binary.Write(&coff, binary.LittleEndian, uint32(relocsOffset))      // PointerToRelocations
	_ = binary.Write(&coff, binary.LittleEndian, uint32(0))                 // PointerToLinenumbers
	_ = binary.Write(&coff, binary.LittleEndian, uint16(len(relocOffsets))) // NumberOfRelocations
	_ = binary.Write(&coff, binary.LittleEndian, uint16(0))                 // NumberOfLinenumbers
	_ = binary.Write(&coff, binary.LittleEndian, uint32(0x40000040))        // CNT_INITIALIZED_DATA | MEM_READ

	// Raw .rsrc section data
	coff.Write(rsrcBytes)

	// COFF relocations (10 bytes each)
	for _, roff := range relocOffsets {
		_ = binary.Write(&coff, binary.LittleEndian, roff)      // VirtualAddress
		_ = binary.Write(&coff, binary.LittleEndian, uint32(0)) // SymbolTableIndex (.rsrc)
		_ = binary.Write(&coff, binary.LittleEndian, relocType) // Type
	}

	// COFF symbol table (1 entry = 18 bytes)
	coff.Write(sectName[:])
	_ = binary.Write(&coff, binary.LittleEndian, uint32(0)) // Value
	_ = binary.Write(&coff, binary.LittleEndian, int16(1))  // SectionNumber (1-based)
	_ = binary.Write(&coff, binary.LittleEndian, uint16(0)) // Type
	coff.WriteByte(3)                                       // StorageClass = IMAGE_SYM_CLASS_STATIC
	coff.WriteByte(0)                                       // NumberOfAuxSymbols

	// Empty COFF string table (4 bytes)
	_ = binary.Write(&coff, binary.LittleEndian, uint32(4))

	return coff.Bytes()
}

func align8(n int) int {
	if rem := n % 8; rem != 0 {
		return n + (8 - rem)
	}
	return n
}
