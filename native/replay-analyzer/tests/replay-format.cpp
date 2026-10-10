#include "replay.h"
#include <iostream>
#include <stdexcept>
#include <vector>

void require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

void append32(std::vector<uint8_t>& bytes, uint32_t value) {
  for (unsigned shift = 0; shift < 32; shift += 8) bytes.push_back(uint8_t(value >> shift));
}

std::vector<uint8_t> readBlock(const std::vector<uint8_t>& bytes, size_t size) {
  bwgame::data_loading::data_reader<> input(bytes.data(), bytes.data() + bytes.size());
  auto reader = bwgame::data_loading::make_replay_file_reader(input);
  std::vector<uint8_t> output(size);
  reader.get_bytes(output.data(), size);
  return output;
}

int main() {
  try {
    // A synthetic two-segment block exercises Remastered zlib decoding, the
    // final partial segment, and the replay container's CRC without game assets.
    std::vector<uint8_t> original(10000);
    for (size_t i = 0; i < original.size(); ++i) original[i] = uint8_t(i % 17);
    std::vector<uint8_t> block;
    bwgame::data_loading::crc32_t checksum;
    append32(block, checksum(original.data(), original.size()));
    append32(block, 2);
    for (size_t offset = 0; offset < original.size(); offset += 8192) {
      auto count = std::min(size_t(8192), original.size() - offset);
      uLongf size = compressBound(uLong(count));
      std::vector<uint8_t> compressed(size);
      require(compress2(compressed.data(), &size, original.data() + offset, uLong(count), 6) == Z_OK,
              "could not construct compressed fixture");
      require(bwgame::data_loading::is_zlib_segment(compressed.data(), size), "zlib not recognized");
      append32(block, uint32_t(size));
      block.insert(block.end(), compressed.begin(), compressed.begin() + size);
    }
    require(readBlock(block, original.size()) == original, "Remastered block did not round trip");
    block[0] ^= 1;
    bool rejected = false;
    try { readBlock(block, original.size()); } catch (const std::exception&) { rejected = true; }
    require(rejected, "corrupt replay CRC was accepted");
    block[0] ^= 1;
    block.resize(block.size() - 3);
    rejected = false;
    try { readBlock(block, original.size()); } catch (const std::exception&) { rejected = true; }
    require(rejected, "truncated replay block was accepted");

    const uint8_t raw[] = {0x78, 0x56, 0x34, 0x12};
    bwgame::data_loading::data_reader<> input(raw, raw + sizeof(raw));
    auto reader = bwgame::data_loading::make_replay_file_reader(input);
    require(bwgame::data_loading::get_unframed_u32(reader) == 0x12345678,
            "Remastered unframed field was decoded incorrectly");
    std::cout << "Remastered replay format tests passed\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
