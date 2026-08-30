package analyzer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

const (
	rawPDBProtocolMagic   = "RPDB0001"
	rawPDBMaxFunctions    = 5_000_000
	rawPDBMaxStringLength = 1 << 20
	rawPDBMaxStringBytes  = 1 << 30
)

type rawPDBFunction struct {
	rva           uint32
	size          uint32
	visibility    string
	name          string
	module        string
	decoratedName string
}

type rawPDBResult struct {
	guid      [16]byte
	age       uint32
	functions []rawPDBFunction
}

func extractRawPDB(ctx context.Context, executable, pdbPath string, pdbData []byte) (rawPDBResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if pdbPath == "" {
		file, err := os.CreateTemp("", "recompiler-rawpdb-*.pdb")
		if err != nil {
			return rawPDBResult{}, fmt.Errorf("create RawPDB input: %w", err)
		}
		pdbPath = file.Name()
		defer os.Remove(pdbPath)
		if _, err := file.Write(pdbData); err != nil {
			file.Close()
			return rawPDBResult{}, fmt.Errorf("write RawPDB input: %w", err)
		}
		if err := file.Close(); err != nil {
			return rawPDBResult{}, fmt.Errorf("close RawPDB input: %w", err)
		}
	}

	command := exec.CommandContext(ctx, executable, pdbPath)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return rawPDBResult{}, fmt.Errorf("open RawPDB output: %w", err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		return rawPDBResult{}, fmt.Errorf("start RawPDB helper: %w", err)
	}

	result, decodeErr := decodeRawPDB(bufio.NewReaderSize(stdout, 1<<20))
	if decodeErr != nil && command.Process != nil {
		_ = command.Process.Kill()
	}
	waitErr := command.Wait()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return rawPDBResult{}, ctxErr
	}
	if waitErr != nil {
		diagnostic := strings.TrimSpace(stderr.String())
		if diagnostic == "" {
			diagnostic = waitErr.Error()
		}
		return rawPDBResult{}, errors.New(diagnostic)
	}
	if decodeErr != nil {
		return rawPDBResult{}, decodeErr
	}
	return result, nil
}

func decodeRawPDB(reader io.Reader) (rawPDBResult, error) {
	var result rawPDBResult
	magic := make([]byte, len(rawPDBProtocolMagic))
	if _, err := io.ReadFull(reader, magic); err != nil {
		return result, fmt.Errorf("read RawPDB protocol header: %w", err)
	}
	if string(magic) != rawPDBProtocolMagic {
		return result, errors.New("RawPDB helper returned an unsupported protocol")
	}
	if _, err := io.ReadFull(reader, result.guid[:]); err != nil {
		return result, fmt.Errorf("read RawPDB GUID: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &result.age); err != nil {
		return result, fmt.Errorf("read RawPDB age: %w", err)
	}
	var count uint32
	if err := binary.Read(reader, binary.LittleEndian, &count); err != nil {
		return result, fmt.Errorf("read RawPDB function count: %w", err)
	}
	if count > rawPDBMaxFunctions {
		return result, fmt.Errorf("RawPDB returned too many functions: %d", count)
	}

	result.functions = make([]rawPDBFunction, 0, count)
	var totalStrings uint64
	for index := uint32(0); index < count; index++ {
		var function rawPDBFunction
		if err := binary.Read(reader, binary.LittleEndian, &function.rva); err != nil {
			return result, fmt.Errorf("read RawPDB function %d RVA: %w", index, err)
		}
		if err := binary.Read(reader, binary.LittleEndian, &function.size); err != nil {
			return result, fmt.Errorf("read RawPDB function %d size: %w", index, err)
		}
		var visibility [1]byte
		if _, err := io.ReadFull(reader, visibility[:]); err != nil {
			return result, fmt.Errorf("read RawPDB function %d visibility: %w", index, err)
		}
		switch visibility[0] {
		case 0:
			function.visibility = "local"
		case 1:
			function.visibility = "global"
		case 2:
			function.visibility = "public"
		default:
			return result, fmt.Errorf("RawPDB function %d has invalid visibility %d", index, visibility[0])
		}
		var err error
		if function.name, err = readRawPDBString(reader, &totalStrings); err != nil {
			return result, fmt.Errorf("read RawPDB function %d name: %w", index, err)
		}
		if function.module, err = readRawPDBString(reader, &totalStrings); err != nil {
			return result, fmt.Errorf("read RawPDB function %d module: %w", index, err)
		}
		if function.decoratedName, err = readRawPDBString(reader, &totalStrings); err != nil {
			return result, fmt.Errorf("read RawPDB function %d decorated name: %w", index, err)
		}
		result.functions = append(result.functions, function)
	}
	return result, nil
}

func readRawPDBString(reader io.Reader, total *uint64) (string, error) {
	var length uint32
	if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
		return "", err
	}
	if length > rawPDBMaxStringLength {
		return "", fmt.Errorf("string is too large: %d bytes", length)
	}
	*total += uint64(length)
	if *total > rawPDBMaxStringBytes {
		return "", errors.New("aggregate strings exceed protocol limit")
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(reader, data); err != nil {
		return "", err
	}
	return string(data), nil
}

func functionsFromRawPDB(raw rawPDBResult, image peInfo) []Function {
	functions := make([]Function, 0, len(raw.functions))
	for _, item := range raw.functions {
		if item.name == "" {
			continue
		}
		section, sectionNumber, offset, ok := image.resolveRVA(item.rva)
		if !ok {
			continue
		}
		functions = append(functions, Function{
			Name: item.name, DecoratedName: item.decoratedName,
			Address: fmt.Sprintf("0x%x", image.imageBase+uint64(item.rva)),
			RVA:     fmt.Sprintf("0x%x", item.rva), Size: item.size, Section: section.name,
			Module: displayBaseName(item.module), Visibility: item.visibility,
			sectionNumber: sectionNumber, offset: offset,
		})
	}
	return sortAndIdentifyFunctions(functions)
}
