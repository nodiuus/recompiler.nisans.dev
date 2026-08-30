#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <limits>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#define NOMINMAX
#include <Windows.h>
#include <fcntl.h>
#include <io.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "PDB.h"
#include "PDB_DBIStream.h"
#include "PDB_DBITypes.h"
#include "PDB_ImageSectionStream.h"
#include "PDB_InfoStream.h"
#include "PDB_ModuleInfoStream.h"
#include "PDB_ModuleSymbolStream.h"
#include "PDB_PublicSymbolStream.h"
#include "PDB_RawFile.h"

namespace {

constexpr char kProtocolMagic[8] = {'R', 'P', 'D', 'B', '0', '0', '0', '1'};

struct MappedFile {
#ifdef _WIN32
  HANDLE file = INVALID_HANDLE_VALUE;
  HANDLE mapping = nullptr;
#else
  int file = -1;
#endif
  void* data = nullptr;
  size_t size = 0;
};

enum class Visibility : uint8_t {
  Local = 0,
  Global = 1,
  Public = 2,
};

struct FunctionRecord {
  uint32_t rva = 0;
  uint32_t size = 0;
  Visibility visibility = Visibility::Local;
  std::string name;
  std::string module;
  std::string decoratedName;
};

MappedFile openMappedFile(const char* path) {
  MappedFile result;
#ifdef _WIN32
  result.file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_READONLY | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
  if (result.file == INVALID_HANDLE_VALUE) return result;

  LARGE_INTEGER size{};
  if (!GetFileSizeEx(result.file, &size) || size.QuadPart <= 0 ||
      static_cast<uint64_t>(size.QuadPart) > std::numeric_limits<size_t>::max()) {
    CloseHandle(result.file);
    result.file = INVALID_HANDLE_VALUE;
    return result;
  }
  result.mapping = CreateFileMappingW(result.file, nullptr, PAGE_READONLY, 0, 0, nullptr);
  if (!result.mapping) {
    CloseHandle(result.file);
    result.file = INVALID_HANDLE_VALUE;
    return result;
  }
  result.data = MapViewOfFile(result.mapping, FILE_MAP_READ, 0, 0, 0);
  if (!result.data) {
    CloseHandle(result.mapping);
    CloseHandle(result.file);
    result.mapping = nullptr;
    result.file = INVALID_HANDLE_VALUE;
    return result;
  }
  result.size = static_cast<size_t>(size.QuadPart);
#else
  result.file = open(path, O_RDONLY);
  if (result.file < 0) return result;
  struct stat info {};
  if (fstat(result.file, &info) != 0 || info.st_size <= 0) {
    close(result.file);
    result.file = -1;
    return result;
  }
  result.size = static_cast<size_t>(info.st_size);
  result.data = mmap(nullptr, result.size, PROT_READ, MAP_PRIVATE, result.file, 0);
  if (result.data == MAP_FAILED) {
    result.data = nullptr;
    close(result.file);
    result.file = -1;
  }
#endif
  return result;
}

void closeMappedFile(MappedFile& file) {
#ifdef _WIN32
  if (file.data) UnmapViewOfFile(file.data);
  if (file.mapping) CloseHandle(file.mapping);
  if (file.file != INVALID_HANDLE_VALUE) CloseHandle(file.file);
  file.mapping = nullptr;
  file.file = INVALID_HANDLE_VALUE;
#else
  if (file.data) munmap(file.data, file.size);
  if (file.file >= 0) close(file.file);
  file.file = -1;
#endif
  file.data = nullptr;
  file.size = 0;
}

const char* errorName(PDB::ErrorCode error) {
  switch (error) {
    case PDB::ErrorCode::Success: return "success";
    case PDB::ErrorCode::InvalidSuperBlock: return "invalid MSF superblock";
    case PDB::ErrorCode::InvalidFreeBlockMap: return "invalid free block map";
    case PDB::ErrorCode::InvalidStream: return "invalid stream";
    case PDB::ErrorCode::InvalidSignature: return "invalid stream signature";
    case PDB::ErrorCode::InvalidStreamIndex: return "invalid stream index";
    case PDB::ErrorCode::InvalidDataSize: return "invalid data size";
    case PDB::ErrorCode::UnknownVersion: return "unknown PDB version";
  }
  return "unknown RawPDB error";
}

bool check(PDB::ErrorCode error, const char* operation) {
  if (error == PDB::ErrorCode::Success) return true;
  std::cerr << operation << ": " << errorName(error) << '\n';
  return false;
}

bool boundedRecordString(const PDB::CodeView::DBI::Record* record, const char* value,
                         std::string& output) {
  const auto* start = reinterpret_cast<const uint8_t*>(record);
  const size_t recordSize = sizeof(uint16_t) + static_cast<size_t>(record->header.size);
  if (recordSize < sizeof(PDB::CodeView::DBI::RecordHeader)) return false;
  const auto* end = start + recordSize;
  const auto* text = reinterpret_cast<const uint8_t*>(value);
  if (text < start || text >= end) return false;
  const void* terminator = std::memchr(text, 0, static_cast<size_t>(end - text));
  if (!terminator) return false;
  output.assign(value, static_cast<const char*>(terminator) - value);
  return !output.empty();
}

std::string moduleName(const PDB::ModuleInfoStream::Module& module) {
  const PDB::ArrayView<char> name = module.GetName();
  if (!name.Decay() || name.GetLength() == 0) return {};
  return std::string(name.Decay(), name.GetLength());
}

bool writeAll(const void* data, size_t size) {
  std::cout.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
  return std::cout.good();
}

bool writeU8(uint8_t value) { return writeAll(&value, sizeof(value)); }

bool writeU32(uint32_t value) {
  const uint8_t bytes[4] = {
      static_cast<uint8_t>(value), static_cast<uint8_t>(value >> 8u),
      static_cast<uint8_t>(value >> 16u), static_cast<uint8_t>(value >> 24u)};
  return writeAll(bytes, sizeof(bytes));
}

bool writeString(const std::string& value) {
  if (value.size() > std::numeric_limits<uint32_t>::max()) return false;
  return writeU32(static_cast<uint32_t>(value.size())) &&
         (value.empty() || writeAll(value.data(), value.size()));
}

bool emitResult(const PDB::GUID& guid, uint32_t age,
                const std::vector<FunctionRecord>& functions) {
#ifdef _WIN32
  if (_setmode(_fileno(stdout), _O_BINARY) == -1) return false;
#endif
  if (functions.size() > std::numeric_limits<uint32_t>::max()) return false;
  if (!writeAll(kProtocolMagic, sizeof(kProtocolMagic)) ||
      !writeAll(&guid, sizeof(guid)) || !writeU32(age) ||
      !writeU32(static_cast<uint32_t>(functions.size()))) {
    return false;
  }
  for (const FunctionRecord& function : functions) {
    if (!writeU32(function.rva) || !writeU32(function.size) ||
        !writeU8(static_cast<uint8_t>(function.visibility)) ||
        !writeString(function.name) || !writeString(function.module) ||
        !writeString(function.decoratedName)) {
      return false;
    }
  }
  std::cout.flush();
  return std::cout.good();
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: rawpdb_analyzer <file.pdb>\n";
    return 2;
  }

  MappedFile mapped = openMappedFile(argv[1]);
  if (!mapped.data) {
    std::cerr << "cannot memory-map PDB\n";
    return 3;
  }

  if (!check(PDB::ValidateFile(mapped.data, mapped.size), "validate PDB")) {
    closeMappedFile(mapped);
    return 4;
  }

  const PDB::RawFile rawFile = PDB::CreateRawFile(mapped.data);
  if (!check(PDB::HasValidDBIStream(rawFile), "validate DBI stream")) {
    closeMappedFile(mapped);
    return 5;
  }

  const PDB::InfoStream infoStream(rawFile);
  if (infoStream.UsesDebugFastLink()) {
    std::cerr << "FASTLINK PDBs are not supported\n";
    closeMappedFile(mapped);
    return 6;
  }
  const PDB::Header* infoHeader = infoStream.GetHeader();
  if (!infoHeader) {
    std::cerr << "PDB info stream has no header\n";
    closeMappedFile(mapped);
    return 7;
  }

  const PDB::DBIStream dbiStream = PDB::CreateDBIStream(rawFile);
  if (!check(dbiStream.HasValidSymbolRecordStream(rawFile), "validate symbol record stream") ||
      !check(dbiStream.HasValidImageSectionStream(rawFile), "validate image section stream") ||
      !check(dbiStream.HasValidPublicSymbolStream(rawFile), "validate public symbol stream")) {
    closeMappedFile(mapped);
    return 8;
  }

  const PDB::ImageSectionStream imageSections = dbiStream.CreateImageSectionStream(rawFile);
  const PDB::ModuleInfoStream modules = dbiStream.CreateModuleInfoStream(rawFile);
  const PDB::CoalescedMSFStream symbolRecords = dbiStream.CreateSymbolRecordStream(rawFile);
  const PDB::PublicSymbolStream publicSymbols = dbiStream.CreatePublicSymbolStream(rawFile);

  std::vector<FunctionRecord> functions;
  std::unordered_map<uint32_t, size_t> byRva;

  for (const PDB::ModuleInfoStream::Module& module : modules.GetModules()) {
    if (!module.HasSymbolStream()) continue;
    const std::string owner = moduleName(module);
    const PDB::ModuleSymbolStream symbols = module.CreateSymbolStream(rawFile);
    symbols.ForEachSymbol([&](const PDB::CodeView::DBI::Record* record) {
      using Kind = PDB::CodeView::DBI::SymbolRecordKind;
      Visibility visibility;
      switch (record->header.kind) {
        case Kind::S_GPROC32:
        case Kind::S_GPROC32_ID:
          visibility = Visibility::Global;
          break;
        case Kind::S_LPROC32:
        case Kind::S_LPROC32_ID:
        case Kind::S_LPROC32_DPC:
        case Kind::S_LPROC32_DPC_ID:
          visibility = Visibility::Local;
          break;
        default:
          return;
      }

      std::string name;
      if (!boundedRecordString(record, record->data.S_LPROC32.name, name)) return;
      const uint32_t rva = imageSections.ConvertSectionOffsetToRVA(
          record->data.S_LPROC32.section, record->data.S_LPROC32.offset);
      if (rva == 0) return;

      const auto existing = byRva.find(rva);
      if (existing != byRva.end()) {
        FunctionRecord& current = functions[existing->second];
        if (current.size == 0 && record->data.S_LPROC32.codeSize != 0) {
          current.size = record->data.S_LPROC32.codeSize;
          current.name = std::move(name);
          current.module = owner;
          current.visibility = visibility;
        }
        return;
      }
      byRva.emplace(rva, functions.size());
      functions.push_back(FunctionRecord{rva, record->data.S_LPROC32.codeSize,
                                         visibility, std::move(name), owner, {}});
    });
  }

  for (const PDB::HashRecord& hash : publicSymbols.GetRecords()) {
    const PDB::CodeView::DBI::Record* record = publicSymbols.GetRecord(symbolRecords, hash);
    using Kind = PDB::CodeView::DBI::SymbolRecordKind;
    if (record->header.kind != Kind::S_PUB32) continue;
    if ((PDB_AS_UNDERLYING(record->data.S_PUB32.flags) &
         PDB_AS_UNDERLYING(PDB::CodeView::DBI::PublicSymbolFlags::Function)) == 0u) {
      continue;
    }
    std::string name;
    if (!boundedRecordString(record, record->data.S_PUB32.name, name)) continue;
    const uint32_t rva = imageSections.ConvertSectionOffsetToRVA(
        record->data.S_PUB32.section, record->data.S_PUB32.offset);
    if (rva == 0) continue;

    const auto existing = byRva.find(rva);
    if (existing != byRva.end()) {
      FunctionRecord& current = functions[existing->second];
      if (current.name != name) current.decoratedName = std::move(name);
      continue;
    }
    byRva.emplace(rva, functions.size());
    functions.push_back(FunctionRecord{rva, 0, Visibility::Public,
                                       std::move(name), {}, {}});
  }

  std::sort(functions.begin(), functions.end(),
            [](const FunctionRecord& left, const FunctionRecord& right) {
              return left.rva < right.rva;
            });

  const PDB::GUID guid = infoHeader->guid;
  const uint32_t age = dbiStream.GetHeader().age;
  closeMappedFile(mapped);

  if (!emitResult(guid, age, functions)) {
    std::cerr << "failed to write analyzer protocol\n";
    return 9;
  }
  return 0;
}
