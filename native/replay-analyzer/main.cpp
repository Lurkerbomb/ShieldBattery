#include "BW/BWData.h"
#include "BWAPI/GameImpl.h"
#include "BWAPI/PlayerImpl.h"

#include <BWAPI.h>
#include <game_types.h>

// Divergence counters kept by the patched engine. See bwl_health.h.
#include <bwl_health.h>

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <filesystem>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

#ifdef __linux__
#include <cerrno>
#include <cstddef>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace {

constexpr int kFrameDurationMs = 42;
constexpr const char* kBackendVersion = "openbw-bwapi-5.2.0";
constexpr int kResourceClusterRadius = 384;
constexpr int kBaseAssociationRadius = 512;
constexpr int kTerritoryNearRadius = 384;
constexpr int kMinimumBaseSiteMinerals = 3000;

#ifdef __linux__
void setHardResourceLimit(int resource, rlim_t value, const char* label) {
  const rlimit limit{value, value};
  if (setrlimit(resource, &limit) != 0) {
    throw std::runtime_error(std::string("process sandbox unavailable at ") + label + " (errno " + std::to_string(errno) + ")");
  }
}

void applyProcessSandbox() {
  setHardResourceLimit(RLIMIT_CORE, 0, "core limit");
  setHardResourceLimit(RLIMIT_CPU, 180, "CPU limit");
  setHardResourceLimit(RLIMIT_AS, static_cast<rlim_t>(2) * 1024 * 1024 * 1024, "address-space limit");
  setHardResourceLimit(RLIMIT_FSIZE, static_cast<rlim_t>(128) * 1024 * 1024, "file-size limit");
  setHardResourceLimit(RLIMIT_NOFILE, 64, "file-descriptor limit");

  if (prctl(PR_SET_DUMPABLE, 0) != 0) {
    throw std::runtime_error("process sandbox unavailable at dump protection (errno " + std::to_string(errno) + ")");
  }
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    throw std::runtime_error("process sandbox unavailable at no-new-privileges (errno " + std::to_string(errno) + ")");
  }

#if defined(__x86_64__)
  constexpr unsigned int kAuditArchitecture = AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
  constexpr unsigned int kAuditArchitecture = AUDIT_ARCH_AARCH64;
#else
#error "The replay simulator sandbox supports only x86_64 and aarch64 Linux"
#endif

#define BWL_DENY_SYSCALL(name) \
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##name, 0, 1), \
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))

  sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, kAuditArchitecture, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
    BWL_DENY_SYSCALL(socket),
    BWL_DENY_SYSCALL(socketpair),
    BWL_DENY_SYSCALL(connect),
    BWL_DENY_SYSCALL(accept),
    BWL_DENY_SYSCALL(accept4),
    BWL_DENY_SYSCALL(bind),
    BWL_DENY_SYSCALL(listen),
    BWL_DENY_SYSCALL(sendto),
    BWL_DENY_SYSCALL(sendmsg),
    BWL_DENY_SYSCALL(recvfrom),
    BWL_DENY_SYSCALL(recvmsg),
    BWL_DENY_SYSCALL(shutdown),
    BWL_DENY_SYSCALL(getsockname),
    BWL_DENY_SYSCALL(getpeername),
    BWL_DENY_SYSCALL(setsockopt),
    BWL_DENY_SYSCALL(getsockopt),
    BWL_DENY_SYSCALL(execve),
    BWL_DENY_SYSCALL(execveat),
    BWL_DENY_SYSCALL(ptrace),
    BWL_DENY_SYSCALL(process_vm_readv),
    BWL_DENY_SYSCALL(process_vm_writev),
#ifdef __NR_io_uring_setup
    BWL_DENY_SYSCALL(io_uring_setup),
    BWL_DENY_SYSCALL(io_uring_enter),
    BWL_DENY_SYSCALL(io_uring_register),
#endif
#ifdef __NR_bpf
    BWL_DENY_SYSCALL(bpf),
#endif
#ifdef __NR_userfaultfd
    BWL_DENY_SYSCALL(userfaultfd),
#endif
    BWL_DENY_SYSCALL(mount),
    BWL_DENY_SYSCALL(umount2),
    BWL_DENY_SYSCALL(pivot_root),
    BWL_DENY_SYSCALL(setns),
    BWL_DENY_SYSCALL(unshare),
#ifdef __NR_open_by_handle_at
    BWL_DENY_SYSCALL(open_by_handle_at),
    BWL_DENY_SYSCALL(name_to_handle_at),
#endif
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
#undef BWL_DENY_SYSCALL

  const sock_fprog program{
    static_cast<unsigned short>(sizeof(filter) / sizeof(filter[0])),
    filter,
  };
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) {
    throw std::runtime_error("process sandbox unavailable at seccomp (errno " + std::to_string(errno) + ")");
  }

  errno = 0;
  const int socketDescriptor = socket(AF_INET, SOCK_STREAM, 0);
  if (socketDescriptor >= 0) {
    close(socketDescriptor);
    throw std::runtime_error("process sandbox network isolation unavailable");
  }
  if (errno != EPERM) {
    throw std::runtime_error("process sandbox network isolation unavailable (errno " + std::to_string(errno) + ")");
  }
}
#else
void applyProcessSandbox() {}
#endif

/** The exact unit that dealt the lethal damage, as a BWAPI id and type name. */
struct KillerUnit {
  int unitId = -1;
  std::string unitType;
  std::string weapon;
};

struct BaseSite {
  int id = -1;
  BWAPI::Position position = BWAPI::Positions::Invalid;
  std::vector<BWAPI::Unit> minerals;
  std::vector<BWAPI::Unit> geysers;
  std::map<int, std::string> relationshipByPlayer;
};

struct SitePlayerState {
  int depots = 0;
  int completedDepots = 0;
  int mineralWorkers = 0;
  int gasWorkers = 0;
  int workersNearby = 0;
  int armySupplyNearestDoubled = 0;
  int armySupplyNearbyDoubled = 0;
  std::map<std::string, int> armySupplyNearestByUnitTypeDoubled;
  std::map<std::string, int> armySupplyNearbyByUnitTypeDoubled;
};

std::string jsonEscape(const std::string& input) {
  std::string output;
  output.reserve(input.size() + 8);
  for (unsigned char character : input) {
    switch (character) {
      case '\\': output += "\\\\"; break;
      case '"': output += "\\\""; break;
      case '\b': output += "\\b"; break;
      case '\f': output += "\\f"; break;
      case '\n': output += "\\n"; break;
      case '\r': output += "\\r"; break;
      case '\t': output += "\\t"; break;
      default:
        if (character >= 0x20) output += static_cast<char>(character);
        break;
    }
  }
  return output;
}

void writeString(std::ostream& output, const std::string& value) {
  output << '"' << jsonEscape(value) << '"';
}

bool isReplayPlayer(BWAPI::Player player) {
  if (!player || player->isNeutral() || player->isObserver()) return false;
  const auto race = player->getRace();
  return race == BWAPI::Races::Terran || race == BWAPI::Races::Protoss || race == BWAPI::Races::Zerg;
}

std::vector<BWAPI::Player> replayPlayers() {
  std::vector<BWAPI::Player> players;
  for (auto player : BWAPI::Broodwar->getPlayers()) {
    if (isReplayPlayer(player)) players.push_back(player);
  }
  std::sort(players.begin(), players.end(), [](BWAPI::Player left, BWAPI::Player right) {
    return left->getID() < right->getID();
  });
  return players;
}

void writePlayerIdentity(std::ostream& output, BWAPI::Player player) {
  output << "{\"id\":" << player->getID() << ",\"name\":";
  writeString(output, player->getName());
  output << ",\"race\":";
  writeString(output, player->getRace().getName());
  const auto start = player->getStartLocation();
  output << ",\"startingPosition\":[" << start.x * 32 + 16 << ',' << start.y * 32 + 16 << ']';
  output << '}';
}

void writeCountMap(std::ostream& output, const std::map<std::string, int>& counts) {
  output << '{';
  bool first = true;
  for (const auto& [name, count] : counts) {
    if (!first) output << ',';
    first = false;
    writeString(output, name);
    output << ':' << count;
  }
  output << '}';
}

void writeSupplyMap(std::ostream& output, const std::map<std::string, int>& doubledSupply) {
  output << '{';
  bool first = true;
  for (const auto& [name, supply] : doubledSupply) {
    if (!first) output << ',';
    first = false;
    writeString(output, name);
    output << ':' << supply / 2.0;
  }
  output << '}';
}

class SnapshotModule final : public BWAPI::AIModule {
 public:
  SnapshotModule(std::string outputPath, int intervalFrames)
      : outputPath_(std::move(outputPath)), intervalFrames_(intervalFrames),
        effectScan_(std::getenv("BWL_EFFECT_SCAN") != nullptr) {}

  void onStart() override {
    output_.open(outputPath_, std::ios::out | std::ios::trunc | std::ios::binary);
    if (!output_) throw std::runtime_error("could not open simulator output file");
    if (!BWAPI::Broodwar->isReplay()) throw std::runtime_error("input is not a replay");
    BWAPI::Broodwar->enableFlag(BWAPI::Flag::CompleteMapInformation);
    players_ = replayPlayers();
    if (players_.size() < 2) throw std::runtime_error("replay contains fewer than two playable players");

    // BWAPI hands out player ids in registration order, which is not the BW
    // slot the engine records against a dropped build order, so keep the map.
    bwgame::health::reset();
    for (auto player : players_) {
      playerIdForSlot_[static_cast<BWAPI::PlayerImpl*>(player)->getIndex()] = player->getID();
      const auto start = player->getStartLocation();
      playerStarts_[player->getID()] = BWAPI::Position(start.x * 32 + 16, start.y * 32 + 16);
    }
    initializeBaseSites();

    output_ << "{\"type\":\"metadata\",\"backendVersion\":\"" << kBackendVersion
            << "\",\"mapName\":";
    writeString(output_, BWAPI::Broodwar->mapName());
    output_ << ",\"replayFrames\":" << BWAPI::Broodwar->getReplayFrameCount()
            << ",\"mapWidthTiles\":" << BWAPI::Broodwar->mapWidth()
            << ",\"mapHeightTiles\":" << BWAPI::Broodwar->mapHeight()
            << ",\"frameDurationMs\":" << kFrameDurationMs
            << ",\"snapshotIntervalFrames\":" << intervalFrames_
            << ",\"emitsUnitEvents\":true"
            << ",\"emitsUnitPositions\":true"
            << ",\"emitsSpatialLedger\":true"
            << ",\"emitsTemporalDamage\":true"
            << ",\"emitsSpellCasts\":true"
            << ",\"territoryNearRadius\":" << kTerritoryNearRadius
            << ",\"upgradeApplicability\":[";
    {
      bool firstUpgrade = true;
      for (const auto& upgrade : BWAPI::UpgradeTypes::allUpgradeTypes()) {
        if (upgrade == BWAPI::UpgradeTypes::None || upgrade == BWAPI::UpgradeTypes::Unknown) continue;
        if (!firstUpgrade) output_ << ',';
        firstUpgrade = false;
        output_ << "{\"upgrade\":";
        writeString(output_, upgrade.getName());
        output_ << ",\"unitTypes\":[";
        bool firstUnit = true;
        for (const auto& unitType : upgrade.whatUses()) {
          if (!firstUnit) output_ << ',';
          firstUnit = false;
          writeString(output_, unitType.getName());
        }
        output_ << "]}";
      }
    }
    output_ << "]"
            << ",\"players\":[";
    for (std::size_t index = 0; index < players_.size(); ++index) {
      if (index) output_ << ',';
      writePlayerIdentity(output_, players_[index]);
    }
    output_ << "],\"baseSites\":";
    writeBaseSites();
    output_ << "}\n";
    for (auto player : players_) {
      for (auto unit : player->getUnits()) registerUnit(unit, true);
    }
    trackFrameState(true);
    sample();
  }

  void onFrame() override {
    trackFrameState(false);
    const int frame = BWAPI::Broodwar->getFrameCount();
    if (frame != lastSampledFrame_ && frame % intervalFrames_ == 0) sample();
    if (effectScan_) scanEffects(frame);
  }

  void onEnd(bool) override {
    if (completed_) return;
    if (BWAPI::Broodwar->getFrameCount() != lastSampledFrame_) sample();
    writeTemporalFacts();
    writeGameResult();
    writeDiagnostics();
    output_ << "{\"type\":\"complete\",\"finalFrame\":" << BWAPI::Broodwar->getFrameCount() << "}\n";
    output_.flush();
    if (!output_) throw std::runtime_error("could not write complete analyzer output");
    completed_ = true;
  }

  void onUnitCreate(BWAPI::Unit unit) override { registerUnit(unit, false); }

  void onUnitComplete(BWAPI::Unit unit) override {
    if (!trackedReplayUnit(unit)) return;
    // BWAPI reports the replay's starting units as completion events while it
    // initializes frame zero. They are already represented by `initial`.
    if (BWAPI::Broodwar->getFrameCount() == 0) return;
    writeUnitEvent("completed", unit);
  }

  void onPlayerLeft(BWAPI::Player player) override {
    if (!isReplayPlayer(player)) return;
    const int frame = BWAPI::Broodwar->getFrameCount();
    output_ << "{\"type\":\"playerEvent\",\"kind\":\"left\",\"frame\":" << frame
            << ",\"timestampMs\":" << frame * kFrameDurationMs
            << ",\"playerId\":" << player->getID() << "}\n";
    playersWhoLeft_.insert(player->getID());
  }

  void onUnitMorph(BWAPI::Unit unit) override {
    if (!trackedReplayUnit(unit)) return;
    const int unitId = unit->getID();
    const std::string previousType = unitTypes_[unitId];
    unitTypes_[unitId] = unit->getType().getName();
    writeUnitEvent("morphed", unit, previousType);
  }

  void onUnitRenegade(BWAPI::Unit unit) override {
    if (!unit || unit->getID() < 0 || !isReplayPlayer(unit->getPlayer())) return;
    const int unitId = unit->getID();
    const int previousPlayerId = unitOwners_.count(unitId) ? unitOwners_[unitId] : -1;
    if (!seenUnits_.count(unitId)) registerUnit(unit, false);
    writeUnitEvent("owner_changed", unit, {}, previousPlayerId);
    unitOwners_[unitId] = unit->getPlayer()->getID();
  }

  void onUnitDestroy(BWAPI::Unit unit) override {
    if (!trackedReplayUnit(unit)) return;
    const int unitId = unit->getID();
    const int ownerId = unitOwners_[unitId];
    const int killerId = lastAttackingPlayerId(unit);
    const auto destroyedType = unit->getType();
    const bool isGameUnit = !destroyedType.isSpell()
        && destroyedType != BWAPI::UnitTypes::Protoss_Scarab
        && destroyedType != BWAPI::UnitTypes::Terran_Nuclear_Missile;
    // Cancel, merge and scripted expiry also reach onUnitDestroy, but unlike a
    // combat death they remove an object that still has hit points. BWAPI's
    // public value is a one-frame cache here, so read the live OpenBW object.
    const auto* implementation = static_cast<BWAPI::UnitImpl*>(unit);
    const bool zeroHitPoints = implementation->bwunit.u
        && implementation->bwunit.u->hp.raw_value <= 0;
    const bool isLoss = isGameUnit && !unit->isHallucination() && zeroHitPoints;
    writeUnitEvent("destroyed", unit, {}, -1, killerId, isLoss, -1, {}, killerUnitOf(unit));
    for (const auto& status : unitStatuses_[unitId]) writeStatusEvent("ended", unit, status);
    if (isLoss) ++unitsLost_[ownerId];
    if (isLoss && killerId >= 0 && killerId != ownerId) ++unitsKilled_[killerId];
    seenUnits_.erase(unitId);
    unitTypes_.erase(unitId);
    unitOwners_.erase(unitId);
    unitTransports_.erase(unitId);
    unitEnemySide_.erase(unitId);
    unitStatuses_.erase(unitId);
  }

 private:
  static long long distanceSquared(BWAPI::Position left, BWAPI::Position right) {
    const long long x = static_cast<long long>(left.x) - right.x;
    const long long y = static_cast<long long>(left.y) - right.y;
    return x * x + y * y;
  }

  static long long stableUnitKey(int index, int generation) {
    return (static_cast<long long>(generation) << 32) | static_cast<unsigned int>(index);
  }

  int unitIdFor(const bwgame::health::unit_reference& reference) const {
    if (reference.index < 0 || reference.generation < 0) return -1;
    const auto found = bwapiIdForOpenBwUnit_.find(stableUnitKey(reference.index, reference.generation));
    return found == bwapiIdForOpenBwUnit_.end() ? -1 : found->second;
  }

  int playerIdForOwner(int owner) const {
    const auto found = playerIdForSlot_.find(owner);
    return found == playerIdForSlot_.end() ? -1 : found->second;
  }

  int nearestSite(BWAPI::Position position, int maximumDistance = -1) const {
    if (!position.isValid() || baseSites_.empty()) return -1;
    int best = -1;
    long long bestDistance = maximumDistance < 0
        ? std::numeric_limits<long long>::max()
        : static_cast<long long>(maximumDistance) * maximumDistance;
    for (const auto& site : baseSites_) {
      const long long distance = distanceSquared(position, site.position);
      if (distance <= bestDistance) {
        bestDistance = distance;
        best = site.id;
      }
    }
    return best;
  }

  int distanceToSite(BWAPI::Position position, int siteId) const {
    if (siteId < 0 || static_cast<std::size_t>(siteId) >= baseSites_.size()) return -1;
    return static_cast<int>(std::llround(std::sqrt(
        static_cast<double>(distanceSquared(position, baseSites_[siteId].position)))));
  }

  void initializeBaseSites() {
    struct ResourceSeed {
      BWAPI::Unit unit;
      bool gas;
    };
    std::vector<ResourceSeed> resources;
    for (auto unit : BWAPI::Broodwar->getStaticMinerals()) {
      if (unit && unit->getPosition().isValid()) resources.push_back({unit, false});
    }
    for (auto unit : BWAPI::Broodwar->getStaticGeysers()) {
      if (unit && unit->getPosition().isValid()) resources.push_back({unit, true});
    }
    if (resources.empty()) return;

    std::vector<int> parent(resources.size());
    for (std::size_t index = 0; index < parent.size(); ++index) parent[index] = static_cast<int>(index);
    auto findRoot = [&](int value) {
      while (parent[value] != value) {
        parent[value] = parent[parent[value]];
        value = parent[value];
      }
      return value;
    };
    for (std::size_t left = 0; left < resources.size(); ++left) {
      for (std::size_t right = left + 1; right < resources.size(); ++right) {
        if (distanceSquared(resources[left].unit->getPosition(), resources[right].unit->getPosition())
            > static_cast<long long>(kResourceClusterRadius) * kResourceClusterRadius) continue;
        const int leftRoot = findRoot(static_cast<int>(left));
        const int rightRoot = findRoot(static_cast<int>(right));
        if (leftRoot != rightRoot) parent[rightRoot] = leftRoot;
      }
    }

    std::map<int, std::vector<ResourceSeed>> clusters;
    for (std::size_t index = 0; index < resources.size(); ++index) {
      clusters[findRoot(static_cast<int>(index))].push_back(resources[index]);
    }
    for (const auto& [_, cluster] : clusters) {
      int mineralCount = 0;
      int initialMinerals = 0;
      long long x = 0;
      long long y = 0;
      BaseSite site;
      for (const auto& resource : cluster) {
        x += resource.unit->getPosition().x;
        y += resource.unit->getPosition().y;
        if (resource.gas) site.geysers.push_back(resource.unit);
        else {
          site.minerals.push_back(resource.unit);
          ++mineralCount;
          initialMinerals += resource.unit->getResources();
        }
      }
      // Mineral walls and isolated map decorations are resources, but not
      // expansion sites. Odyssey's mineral walls look like seven-field
      // clusters geometrically but hold only 554 minerals total; real corpus
      // bases hold thousands. Require both a base-sized cluster and economy.
      if (mineralCount < 3 || initialMinerals < kMinimumBaseSiteMinerals) continue;
      site.position = BWAPI::Position(
          static_cast<int>(x / static_cast<long long>(cluster.size())),
          static_cast<int>(y / static_cast<long long>(cluster.size())));
      baseSites_.push_back(std::move(site));
    }
    std::sort(baseSites_.begin(), baseSites_.end(), [](const BaseSite& left, const BaseSite& right) {
      return std::tie(left.position.y, left.position.x) < std::tie(right.position.y, right.position.x);
    });
    for (std::size_t index = 0; index < baseSites_.size(); ++index) baseSites_[index].id = static_cast<int>(index);

    for (auto player : players_) {
      const int playerId = player->getID();
      const BWAPI::Position start = playerStarts_.at(playerId);
      const int mainSite = nearestSite(start);
      int naturalSite = -1;
      long long naturalDistance = std::numeric_limits<long long>::max();
      for (const auto& site : baseSites_) {
        if (site.id == mainSite || !BWAPI::Broodwar->hasPath(start, site.position)) continue;
        const long long distance = distanceSquared(start, site.position);
        if (distance < naturalDistance) {
          naturalDistance = distance;
          naturalSite = site.id;
        }
      }
      if (naturalSite < 0) {
        for (const auto& site : baseSites_) {
          if (site.id == mainSite) continue;
          const long long distance = distanceSquared(start, site.position);
          if (distance < naturalDistance) {
            naturalDistance = distance;
            naturalSite = site.id;
          }
        }
      }
      for (auto& site : baseSites_) {
        site.relationshipByPlayer[playerId] = site.id == mainSite ? "main"
            : site.id == naturalSite ? "natural"
            : "other";
      }
    }
  }

  void writeBaseSites() {
    output_ << '[';
    for (std::size_t index = 0; index < baseSites_.size(); ++index) {
      if (index) output_ << ',';
      const auto& site = baseSites_[index];
      int initialMinerals = 0;
      int initialGas = 0;
      for (auto resource : site.minerals) initialMinerals += resource->getResources();
      for (auto resource : site.geysers) initialGas += resource->getResources();
      output_ << "{\"id\":" << site.id
              << ",\"position\":[" << site.position.x << ',' << site.position.y << ']'
              << ",\"mineralFieldCount\":" << site.minerals.size()
              << ",\"geyserCount\":" << site.geysers.size()
              << ",\"initialMinerals\":" << initialMinerals
              << ",\"initialGas\":" << initialGas
              << ",\"relationships\":[";
      bool first = true;
      for (auto player : players_) {
        if (!first) output_ << ',';
        first = false;
        output_ << "{\"playerId\":" << player->getID() << ",\"kind\":";
        writeString(output_, site.relationshipByPlayer.at(player->getID()));
        output_ << ",\"distanceFromStart\":" << distanceToSite(playerStarts_.at(player->getID()), site.id) << '}';
      }
      output_ << "]}";
    }
    output_ << ']';
  }

  bool trackedReplayUnit(BWAPI::Unit unit) const {
    return unit && unit->getID() >= 0 && seenUnits_.count(unit->getID())
        && unitOwners_.count(unit->getID());
  }

  bool isEnemySide(int playerId, BWAPI::Position position) const {
    if (players_.size() != 2 || !position.isValid() || !playerStarts_.count(playerId)) return false;
    const int opponentId = players_[0]->getID() == playerId ? players_[1]->getID() : players_[0]->getID();
    const auto opponent = playerStarts_.find(opponentId);
    if (opponent == playerStarts_.end()) return false;
    return distanceSquared(position, opponent->second) < distanceSquared(position, playerStarts_.at(playerId));
  }

  BWAPI::Position effectivePosition(BWAPI::Unit unit) const {
    if (!unit) return BWAPI::Positions::Invalid;
    const auto transport = unit->getTransport();
    return transport ? transport->getPosition() : unit->getPosition();
  }

  KillerUnit killerUnitOf(BWAPI::Unit unit) const {
    const auto* implementation = static_cast<BWAPI::UnitImpl*>(unit);
    if (!implementation->bwunit.u) return {};
    const auto record = bwgame::health::killer_of(
        (int)implementation->bwunit.u->index,
        (int)implementation->bwunit.u->unit_id_generation);
    // A weapon is recorded even where no unit survives to be named, which is
    // what keeps a Spider Mine or a burning building from reading as an
    // unexplained death.
    const std::string weapon = weaponName(record.weapon_id);
    if (record.killer_index < 0) return { -1, std::string(), weapon };
    // The killer's own object may already be gone - a Scarab detonates, an
    // Interceptor is recalled - so its type is taken from the record rather
    // than looked up now. Its id is best-effort for the same reason.
    const auto known = bwapiIdForOpenBwIndex_.find(record.killer_index);
    return {
      known == bwapiIdForOpenBwIndex_.end() ? -1 : known->second,
      record.killer_unit_type_id < 0 ? std::string() : BWAPI::UnitType(record.killer_unit_type_id).getName(),
      weapon,
    };
  }

  static std::string weaponName(int weaponId) {
    if (weaponId == bwgame::health::weapon_structure_fire) return "Structure Fire";
    if (weaponId < 0) return {};
    const auto weapon = BWAPI::WeaponType(weaponId);
    return weapon == BWAPI::WeaponTypes::Unknown ? std::string() : weapon.getName();
  }

  int lastAttackingPlayerId(BWAPI::Unit unit) const {
    if (!unit) return -1;
    const auto* implementation = static_cast<BWAPI::UnitImpl*>(unit);
    if (!implementation->bwunit.u) return -1;
    const int slot = implementation->bwunit.u->last_attacking_player;
    const auto player = playerIdForSlot_.find(slot);
    return player == playerIdForSlot_.end() ? -1 : player->second;
  }

  void writeUnitEvent(const char* kind,
                      BWAPI::Unit unit,
                      const std::string& previousType = {},
                      int previousPlayerId = -1,
                      int killerPlayerId = -1,
                      bool loss = false,
                      int transportId = -1,
                      const std::string& transportType = {},
                      const KillerUnit& killer = {}) {
    if (!output_ || completed_ || !unit || unit->getID() < 0) return;
    const int frame = BWAPI::Broodwar->getFrameCount();
    const int unitId = unit->getID();
    const auto player = unit->getPlayer();
    const int playerId = player && isReplayPlayer(player)
        ? player->getID()
        : (unitOwners_.count(unitId) ? unitOwners_[unitId] : -1);
    const std::string type = unitTypes_.count(unitId) ? unitTypes_[unitId] : unit->getType().getName();
    const auto position = effectivePosition(unit);
    const auto unitType = unit->getType();
    const auto buildType = unit->getBuildType();
    output_ << "{\"type\":\"unitEvent\",\"kind\":";
    writeString(output_, kind);
    output_ << ",\"frame\":" << frame
            << ",\"timestampMs\":" << frame * kFrameDurationMs
            << ",\"unitId\":" << unitId
            << ",\"playerId\":" << playerId
            << ",\"unitType\":";
    writeString(output_, type);
    output_ << ",\"position\":[" << position.x << ',' << position.y << ']'
            << ",\"supply\":" << unitType.supplyRequired() / 2.0
            << ",\"playerSupply\":" << (player ? player->supplyUsed() / 2.0 : 0.0)
            << ",\"worker\":" << (unitType.isWorker() ? "true" : "false")
            << ",\"building\":" << (unitType.isBuilding() ? "true" : "false")
            << ",\"completed\":" << (unit->isCompleted() ? "true" : "false")
            << ",\"enemySide\":" << (isEnemySide(playerId, position) ? "true" : "false");
    if (buildType != BWAPI::UnitTypes::None && buildType != BWAPI::UnitTypes::Unknown) {
      output_ << ",\"buildType\":";
      writeString(output_, buildType.getName());
    }
    if (!previousType.empty()) {
      output_ << ",\"previousUnitType\":";
      writeString(output_, previousType);
    }
    if (previousPlayerId >= 0) output_ << ",\"previousPlayerId\":" << previousPlayerId;
    if (killerPlayerId >= 0) output_ << ",\"killerPlayerId\":" << killerPlayerId;
    if (!killer.unitType.empty()) {
      output_ << ",\"killerUnitType\":";
      writeString(output_, killer.unitType);
      if (killer.unitId >= 0) output_ << ",\"killerUnitId\":" << killer.unitId;
    }
    if (!killer.weapon.empty()) {
      output_ << ",\"killerWeapon\":";
      writeString(output_, killer.weapon);
    }
    if (std::string(kind) == "destroyed") output_ << ",\"loss\":" << (loss ? "true" : "false");
    if (transportId >= 0) {
      output_ << ",\"transportId\":" << transportId << ",\"transportType\":";
      writeString(output_, transportType);
    }
    output_ << "}\n";
  }

  std::set<std::string> currentStatuses(BWAPI::Unit unit) const {
    std::set<std::string> statuses;
    if (!unit) return statuses;
    const auto* implementation = static_cast<BWAPI::UnitImpl*>(unit);
    const auto* raw = implementation->bwunit.u;
    if (!raw) return statuses;
    if (raw->plague_timer) statuses.insert("Plague");
    if (raw->irradiate_timer) statuses.insert("Irradiate");
    if (raw->ensnare_timer) statuses.insert("Ensnare");
    if (raw->stasis_timer) statuses.insert("Stasis Field");
    if (raw->lockdown_timer) statuses.insert("Lockdown");
    if (raw->maelstrom_timer) statuses.insert("Maelstrom");
    if (raw->defensive_matrix_hp.raw_value > 0) statuses.insert("Defensive Matrix");
    if (raw->acid_spore_count) statuses.insert("Acid Spores");
    if (raw->parasite_flags) statuses.insert("Parasite");
    if (raw->blinded_by) statuses.insert("Optical Flare");
    return statuses;
  }

  bwgame::health::unit_reference statusSource(BWAPI::Unit unit, const std::string& status) const {
    if (!unit) return {};
    int weaponId = bwgame::health::weapon_unknown;
    if (status == "Plague") weaponId = static_cast<int>(BWAPI::WeaponTypes::Plague);
    else if (status == "Irradiate") weaponId = static_cast<int>(BWAPI::WeaponTypes::Irradiate);
    if (weaponId == bwgame::health::weapon_unknown) return {};
    const auto* implementation = static_cast<BWAPI::UnitImpl*>(unit);
    const auto* raw = implementation->bwunit.u;
    if (!raw) return {};
    return bwgame::health::effect_source_of(
        weaponId, static_cast<int>(raw->index), static_cast<int>(raw->unit_id_generation));
  }

  // Opt-in raw capture for the Pluto observation encoders, which take values
  // rather than offsets. Every field is emitted under its own bwgame name; the
  // encoders' ten-counter *ordering* is deliberately not imposed here, because
  // that correspondence is not established. See the plutonic repository's
  // native/pluto/OPENBW_CAPTURE.md.
  // Reports every frame at which any unit carries a live spell effect, so a
  // cross-engine comparison can be pointed at one instead of guessing.
  void scanEffects(int frame) {
    for (BWAPI::Unit unit : BWAPI::Broodwar->getAllUnits()) {
      if (!unit) continue;
      const auto* raw = static_cast<BWAPI::UnitImpl*>(unit)->bwunit.u;
      if (!raw || !raw->unit_type) continue;
      const int timers[] = {raw->stim_timer, raw->ensnare_timer, raw->lockdown_timer,
                            raw->irradiate_timer, raw->stasis_timer, raw->plague_timer,
                            raw->storm_timer, raw->maelstrom_timer,
                            raw->defensive_matrix_timer, raw->acid_spore_count};
      static const char* names[] = {"stim","ensnare","lockdown","irradiate","stasis",
                                    "plague","storm","maelstrom","matrix","acidSpores"};
      for (int i = 0; i < 10; ++i) {
        if (!timers[i]) continue;
        output_ << "{\"type\":\"effectScan\",\"frame\":" << frame
                << ",\"effect\":\"" << names[i] << "\",\"value\":" << timers[i]
                << ",\"unitTypeId\":" << static_cast<int>(raw->unit_type->id)
                << ",\"owner\":" << raw->owner << "}\n";
      }
    }
  }


















  void writeStatusEvent(const char* kind, BWAPI::Unit unit, const std::string& status) {
    if (!unit || !trackedReplayUnit(unit)) return;
    const int frame = BWAPI::Broodwar->getFrameCount();
    const auto position = effectivePosition(unit);
    const int siteId = nearestSite(position);
    const auto source = statusSource(unit, status);
    const int sourcePlayerId = playerIdForOwner(source.owner);
    const int sourceUnitId = unitIdFor(source);
    output_ << "{\"type\":\"statusEvent\",\"kind\":";
    writeString(output_, kind);
    output_ << ",\"status\":";
    writeString(output_, status);
    output_ << ",\"frame\":" << frame
            << ",\"timestampMs\":" << frame * kFrameDurationMs
            << ",\"unitId\":" << unit->getID()
            << ",\"playerId\":" << unitOwners_.at(unit->getID())
            << ",\"unitType\":";
    writeString(output_, unitTypes_.at(unit->getID()));
    output_ << ",\"position\":[" << position.x << ',' << position.y << ']';
    if (siteId >= 0) {
      output_ << ",\"nearestBaseSiteId\":" << siteId
              << ",\"distanceToBaseSite\":" << distanceToSite(position, siteId);
    }
    if (sourcePlayerId >= 0) output_ << ",\"sourcePlayerId\":" << sourcePlayerId;
    if (sourceUnitId >= 0) output_ << ",\"sourceUnitId\":" << sourceUnitId;
    const std::string sourceType = unitTypeName(source.unit_type_id);
    if (!sourceType.empty()) {
      output_ << ",\"sourceUnitType\":";
      writeString(output_, sourceType);
    }
    output_ << "}\n";
  }

  void trackStatuses(BWAPI::Unit unit, bool initial) {
    const int unitId = unit->getID();
    const auto current = currentStatuses(unit);
    const auto previous = unitStatuses_[unitId];
    for (const auto& status : current) {
      if (!previous.count(status)) writeStatusEvent("started", unit, status);
    }
    if (!initial) {
      for (const auto& status : previous) {
        if (!current.count(status)) writeStatusEvent("ended", unit, status);
      }
    }
    unitStatuses_[unitId] = current;
  }

  BWAPI::Position workerResourcePosition(BWAPI::Unit unit) const {
    if (!unit || !unit->getType().isWorker()) return BWAPI::Positions::Invalid;
    const auto* implementation = static_cast<BWAPI::UnitImpl*>(unit);
    const auto* raw = implementation->bwunit.u;
    if (!raw) return BWAPI::Positions::Invalid;
    const auto* target = raw->worker.target_resource_unit
        ? raw->worker.target_resource_unit
        : raw->worker.gather_target;
    if (target && target->sprite) return BWAPI::Position(target->sprite->position.x, target->sprite->position.y);
    return BWAPI::Positions::Invalid;
  }

  void writeTerritorySnapshot(int frame) {
    std::map<std::pair<int, int>, SitePlayerState> states;
    for (const auto& site : baseSites_) {
      for (auto player : players_) states[{site.id, player->getID()}] = {};
    }

    for (auto player : players_) {
      const int playerId = player->getID();
      for (auto unit : player->getUnits()) {
        if (!unit || !unit->exists()) continue;
        const auto type = unit->getType();
        const auto position = effectivePosition(unit);
        if (!position.isValid()) continue;

        if (type.isResourceDepot() && !unit->isLifted()) {
          const int siteId = nearestSite(position, kBaseAssociationRadius);
          if (siteId >= 0) {
            auto& state = states[{siteId, playerId}];
            ++state.depots;
            if (unit->isCompleted()) ++state.completedDepots;
          }
        }

        if (type.isWorker()) {
          for (const auto& site : baseSites_) {
            if (distanceSquared(position, site.position)
                <= static_cast<long long>(kTerritoryNearRadius) * kTerritoryNearRadius) {
              ++states[{site.id, playerId}].workersNearby;
            }
          }
          if (unit->isGatheringMinerals() || unit->isGatheringGas()) {
            BWAPI::Position resourcePosition = workerResourcePosition(unit);
            if (!resourcePosition.isValid()) resourcePosition = position;
            const int siteId = nearestSite(resourcePosition, kBaseAssociationRadius);
            if (siteId >= 0) {
              auto& state = states[{siteId, playerId}];
              if (unit->isGatheringMinerals()) ++state.mineralWorkers;
              else ++state.gasWorkers;
            }
          }
          continue;
        }

        if (!type.isBuilding() && unit->isCompleted() && type.supplyRequired() > 0) {
          const auto unitType = type.getName();
          const int nearest = nearestSite(position);
          if (nearest >= 0) {
            auto& state = states[{nearest, playerId}];
            state.armySupplyNearestDoubled += type.supplyRequired();
            state.armySupplyNearestByUnitTypeDoubled[unitType] += type.supplyRequired();
          }
          for (const auto& site : baseSites_) {
            if (distanceSquared(position, site.position)
                <= static_cast<long long>(kTerritoryNearRadius) * kTerritoryNearRadius) {
              auto& state = states[{site.id, playerId}];
              state.armySupplyNearbyDoubled += type.supplyRequired();
              state.armySupplyNearbyByUnitTypeDoubled[unitType] += type.supplyRequired();
            }
          }
        }
      }
    }

    output_ << "{\"type\":\"territorySnapshot\",\"frame\":" << frame
            << ",\"timestampMs\":" << frame * kFrameDurationMs << ",\"sites\":[";
    for (std::size_t index = 0; index < baseSites_.size(); ++index) {
      if (index) output_ << ',';
      const auto& site = baseSites_[index];
      int mineralsRemaining = 0;
      int gasRemaining = 0;
      for (auto resource : site.minerals) mineralsRemaining += std::max(0, resource->getResources());
      for (auto resource : site.geysers) gasRemaining += std::max(0, resource->getResources());
      output_ << "{\"siteId\":" << site.id
              << ",\"mineralsRemaining\":" << mineralsRemaining
              << ",\"gasRemaining\":" << gasRemaining
              << ",\"players\":[";
      for (std::size_t playerIndex = 0; playerIndex < players_.size(); ++playerIndex) {
        if (playerIndex) output_ << ',';
        const int playerId = players_[playerIndex]->getID();
        const auto& state = states.at({site.id, playerId});
        output_ << "{\"playerId\":" << playerId
                << ",\"depots\":" << state.depots
                << ",\"completedDepots\":" << state.completedDepots
                << ",\"mineralWorkers\":" << state.mineralWorkers
                << ",\"gasWorkers\":" << state.gasWorkers
                << ",\"workersNearby\":" << state.workersNearby
                << ",\"armySupplyNearest\":" << state.armySupplyNearestDoubled / 2.0
                << ",\"armySupplyNearby\":" << state.armySupplyNearbyDoubled / 2.0
                << ",\"armySupplyNearestByUnitType\":";
        writeSupplyMap(output_, state.armySupplyNearestByUnitTypeDoubled);
        output_ << ",\"armySupplyNearbyByUnitType\":";
        writeSupplyMap(output_, state.armySupplyNearbyByUnitTypeDoubled);
        output_ << '}';
      }
      output_ << "]}";
    }
    output_ << "]}\n";
  }

  void writeUnitPositionSnapshot(int frame) {
    constexpr int kSpatialIntervalFrames = 120;
    if (lastUnitPositionFrame_ >= 0 && frame - lastUnitPositionFrame_ < kSpatialIntervalFrames) return;
    output_ << "{\"type\":\"unitPositionSnapshot\",\"frame\":" << frame
            << ",\"timestampMs\":" << frame * kFrameDurationMs << ",\"units\":[";
    bool first = true;
    for (auto player : players_) {
      for (auto unit : player->getUnits()) {
        if (!unit || !unit->exists() || !unit->isCompleted()) continue;
        const auto type = unit->getType();
        if (type.isWorker() || type.isBuilding() || type.supplyRequired() <= 0) continue;
        const auto position = effectivePosition(unit);
        if (!position.isValid()) continue;
        if (!first) output_ << ',';
        first = false;
        output_ << "{\"unitId\":" << unit->getID()
                << ",\"playerId\":" << player->getID()
                << ",\"unitType\":";
        writeString(output_, type.getName());
        output_ << ",\"position\":[" << position.x << ',' << position.y << ']'
                << ",\"supply\":" << type.supplyRequired() / 2.0 << '}';
      }
    }
    output_ << "]}\n";
    lastUnitPositionFrame_ = frame;
  }

  void registerUnit(BWAPI::Unit unit, bool initial) {
    if (!unit || unit->getID() < 0 || !isReplayPlayer(unit->getPlayer())) return;
    const int unitId = unit->getID();
    if (seenUnits_.count(unitId)) return;
    seenUnits_.insert(unitId);
    unitTypes_[unitId] = unit->getType().getName();
    unitOwners_[unitId] = unit->getPlayer()->getID();
    const auto transport = unit->getTransport();
    unitTransports_[unitId] = transport ? transport->getID() : -1;
    unitEnemySide_[unitId] = isEnemySide(unitOwners_[unitId], effectivePosition(unit));
    // The killer table is keyed by OpenBW container index, because at the kill
    // site that is all there is. Entries are kept after the unit dies: a Scarab
    // or an Interceptor is routinely gone before its victim's destroy callback.
    const auto* implementation = static_cast<BWAPI::UnitImpl*>(unit);
    if (implementation->bwunit.u) {
      const int index = static_cast<int>(implementation->bwunit.u->index);
      const int generation = static_cast<int>(implementation->bwunit.u->unit_id_generation);
      bwapiIdForOpenBwIndex_[index] = unitId;
      bwapiIdForOpenBwUnit_[stableUnitKey(index, generation)] = unitId;
    }
    writeUnitEvent(initial ? "initial" : "created", unit);
  }

  void trackFrameState(bool initial) {
    std::map<int, int> enemySupplyDoubled;
    for (auto player : players_) enemySupplyDoubled[player->getID()] = 0;
    for (auto player : players_) {
      for (auto unit : player->getUnits()) {
        if (!unit || !unit->exists()) continue;
        registerUnit(unit, initial);
        if (!trackedReplayUnit(unit)) continue;
        const int unitId = unit->getID();
        const auto transport = unit->getTransport();
        const int transportId = transport ? transport->getID() : -1;
        const int previousTransportId = unitTransports_[unitId];
        if (transportId != previousTransportId) {
          if (previousTransportId >= 0) {
            writeUnitEvent("unloaded", unit, {}, -1, -1, false, previousTransportId,
                           unitTypes_.count(previousTransportId) ? unitTypes_[previousTransportId] : "Unknown");
          }
          if (transportId >= 0) {
            writeUnitEvent("loaded", unit, {}, -1, -1, false, transportId,
                           transport ? transport->getType().getName() : "Unknown");
          }
          unitTransports_[unitId] = transportId;
        }
        trackStatuses(unit, initial);

        const bool enemySide = isEnemySide(player->getID(), effectivePosition(unit));
        if (!initial && enemySide != unitEnemySide_[unitId]) {
          writeUnitEvent(enemySide ? "entered_enemy_territory" : "left_enemy_territory", unit);
        }
        unitEnemySide_[unitId] = enemySide;
        const auto type = unit->getType();
        if (enemySide && unit->isCompleted() && !type.isWorker() && !type.isBuilding()
            && type.supplyRequired() > 0) {
          enemySupplyDoubled[player->getID()] += type.supplyRequired();
        }
      }
    }
    const int frame = BWAPI::Broodwar->getFrameCount();
    for (const auto& [playerId, supplyDoubled] : enemySupplyDoubled) {
      if (!initial && enemySideSupplyDoubled_.count(playerId)
          && enemySideSupplyDoubled_[playerId] == supplyDoubled) continue;
      enemySideSupplyDoubled_[playerId] = supplyDoubled;
      output_ << "{\"type\":\"armyPosition\",\"frame\":" << frame
              << ",\"timestampMs\":" << frame * kFrameDurationMs
              << ",\"playerId\":" << playerId
              << ",\"enemySideArmySupply\":" << supplyDoubled / 2.0 << "}\n";
    }
  }

  static std::string unitTypeName(int unitTypeId) {
    if (unitTypeId < 0) return {};
    const auto type = BWAPI::UnitType(unitTypeId);
    return type == BWAPI::UnitTypes::Unknown ? std::string() : type.getName();
  }

  void writeTemporalFacts() {
    const auto& health = bwgame::health::get();
    for (const auto& cast : health.spell_casts) {
      const int playerId = playerIdForOwner(cast.caster.owner);
      const auto technology = BWAPI::TechType(cast.tech_type_id);
      if (playerId < 0 || technology == BWAPI::TechTypes::Unknown
          || technology == BWAPI::TechTypes::None) continue;
      const int casterUnitId = unitIdFor(cast.caster);
      const int targetPlayerId = playerIdForOwner(cast.target.owner);
      const int targetUnitId = unitIdFor(cast.target);
      const BWAPI::Position targetPosition(cast.target_x, cast.target_y);
      const int siteId = nearestSite(targetPosition);
      output_ << "{\"type\":\"spellCastEvent\",\"frame\":" << cast.frame
              << ",\"timestampMs\":" << cast.frame * kFrameDurationMs
              << ",\"technology\":";
      writeString(output_, technology.getName());
      output_ << ",\"playerId\":" << playerId
              << ",\"casterUnitType\":";
      writeString(output_, unitTypeName(cast.caster.unit_type_id));
      if (casterUnitId >= 0) output_ << ",\"casterUnitId\":" << casterUnitId;
      output_ << ",\"casterPosition\":[" << cast.caster.x << ',' << cast.caster.y << ']'
              << ",\"targetPosition\":[" << cast.target_x << ',' << cast.target_y << ']'
              << ",\"energyBefore\":" << cast.raw_energy_before / 256.0
              << ",\"energyAfter\":" << cast.raw_energy_after / 256.0
              << ",\"energyCost\":" << (cast.raw_energy_before - cast.raw_energy_after) / 256.0;
      if (targetPlayerId >= 0) output_ << ",\"targetPlayerId\":" << targetPlayerId;
      if (targetUnitId >= 0) output_ << ",\"targetUnitId\":" << targetUnitId;
      const std::string targetType = unitTypeName(cast.target.unit_type_id);
      if (!targetType.empty()) {
        output_ << ",\"targetUnitType\":";
        writeString(output_, targetType);
      }
      if (siteId >= 0) {
        output_ << ",\"nearestBaseSiteId\":" << siteId
                << ",\"distanceToBaseSite\":" << distanceToSite(targetPosition, siteId);
      }
      output_ << "}\n";
    }

    for (const auto& damage : health.damage_applications) {
      const int victimPlayerId = playerIdForOwner(damage.victim.owner);
      const std::string weapon = weaponName(damage.weapon_id);
      if (victimPlayerId < 0 || weapon.empty()) continue;
      const int sourcePlayerId = playerIdForOwner(damage.source.owner);
      const int sourceUnitId = unitIdFor(damage.source);
      const int victimUnitId = unitIdFor(damage.victim);
      const BWAPI::Position position(damage.victim.x, damage.victim.y);
      const int siteId = nearestSite(position);
      output_ << "{\"type\":\"damageEvent\",\"frame\":" << damage.frame
              << ",\"timestampMs\":" << damage.frame * kFrameDurationMs
              << ",\"weapon\":";
      writeString(output_, weapon);
      output_ << ",\"victimPlayerId\":" << victimPlayerId;
      if (victimUnitId >= 0) output_ << ",\"victimUnitId\":" << victimUnitId;
      const std::string victimType = unitTypeName(damage.victim.unit_type_id);
      if (!victimType.empty()) {
        output_ << ",\"victimUnitType\":";
        writeString(output_, victimType);
        const auto type = BWAPI::UnitType(damage.victim.unit_type_id);
        output_ << ",\"victimWorker\":" << (type.isWorker() ? "true" : "false")
                << ",\"victimBuilding\":" << (type.isBuilding() ? "true" : "false");
      }
      if (sourcePlayerId >= 0) output_ << ",\"sourcePlayerId\":" << sourcePlayerId;
      if (sourceUnitId >= 0) output_ << ",\"sourceUnitId\":" << sourceUnitId;
      const std::string sourceType = unitTypeName(damage.source.unit_type_id);
      if (!sourceType.empty()) {
        output_ << ",\"sourceUnitType\":";
        writeString(output_, sourceType);
      }
      output_ << ",\"position\":[" << position.x << ',' << position.y << ']'
              << ",\"hitPointDamage\":" << damage.raw_hit_point_damage / 256.0
              << ",\"shieldDamage\":" << damage.raw_shield_damage / 256.0
              << ",\"damage\":"
              << (damage.raw_hit_point_damage + damage.raw_shield_damage) / 256.0
              << ",\"lethal\":" << (damage.lethal ? "true" : "false");
      if (siteId >= 0) {
        output_ << ",\"nearestBaseSiteId\":" << siteId
                << ",\"distanceToBaseSite\":" << distanceToSite(position, siteId);
      }
      output_ << "}\n";
    }

    for (const auto& delivery : health.resource_deliveries) {
      const int playerId = playerIdForOwner(delivery.worker.owner);
      if (playerId < 0 || delivery.amount <= 0) continue;
      BWAPI::Position resourcePosition(delivery.resource.x, delivery.resource.y);
      const BWAPI::Position depotPosition(delivery.depot.x, delivery.depot.y);
      int siteId = nearestSite(resourcePosition, kBaseAssociationRadius);
      if (siteId < 0) siteId = nearestSite(depotPosition, kBaseAssociationRadius);
      output_ << "{\"type\":\"resourceDelivery\",\"frame\":" << delivery.frame
              << ",\"timestampMs\":" << delivery.frame * kFrameDurationMs
              << ",\"playerId\":" << playerId
              << ",\"resource\":";
      writeString(output_, delivery.kind == bwgame::health::resource_kind::minerals ? "minerals" : "gas");
      output_ << ",\"amount\":" << delivery.amount;
      const int workerId = unitIdFor(delivery.worker);
      const int depotId = unitIdFor(delivery.depot);
      if (workerId >= 0) output_ << ",\"workerUnitId\":" << workerId;
      if (depotId >= 0) output_ << ",\"depotUnitId\":" << depotId;
      if (siteId >= 0) output_ << ",\"baseSiteId\":" << siteId;
      output_ << ",\"depotPosition\":[" << depotPosition.x << ',' << depotPosition.y << ']';
      if (resourcePosition.isValid()) {
        output_ << ",\"resourcePosition\":[" << resourcePosition.x << ',' << resourcePosition.y << ']';
      }
      output_ << "}\n";
    }
  }

  // OpenBW can drift from the engine that produced a replay without ever
  // failing, and a drifted simulation still emits plausible-looking snapshots.
  // These two counters are how a consumer tells the difference. They are
  // reported once, at the end, with the frames of the first offences so the
  // divergence can be located in time.
  void writeDiagnostics() {
    const auto& health = bwgame::health::get();
    const std::size_t definiteErrors = health.tags_foreign + health.tags_building
        + health.tags_dead + health.tags_unallocated;
    auto writeIntegrityCommandCounts = [&](const std::map<std::pair<int, int>, std::size_t>& commands) {
      output_ << '[';
      bool firstCommand = true;
      for (const auto& [key, count] : commands) {
        const auto& [frame, owner] = key;
        const auto playerId = playerIdForSlot_.find(owner);
        if (playerId == playerIdForSlot_.end()) continue;
        if (!firstCommand) output_ << ',';
        firstCommand = false;
        output_ << "{\"frame\":" << frame
                << ",\"playerId\":" << playerId->second
                << ",\"count\":" << count << '}';
      }
      output_ << ']';
    };

    output_ << "{\"type\":\"diagnostics\",\"selectionTags\":{"
            << "\"total\":" << health.tags_total
            << ",\"clean\":" << health.tags_clean
            << ",\"ambiguous\":" << health.tags_ambiguous
            << ",\"foreign\":" << health.tags_foreign
            << ",\"building\":" << health.tags_building
            << ",\"dead\":" << health.tags_dead
            << ",\"unallocated\":" << health.tags_unallocated
            << ",\"definiteErrors\":" << definiteErrors
            << ",\"firstDefiniteErrorFrame\":" << health.first_definite_error_frame
            << ",\"firstUnitDeficitFrame\":" << health.first_unit_deficit_frame
            << ",\"firstErrorsTruncated\":"
            << (definiteErrors > health.first_tag_errors.size() ? "true" : "false")
            << ",\"firstErrors\":[";
    bool firstError = true;
    for (const auto& error : health.first_tag_errors) {
      if (!firstError) output_ << ',';
      firstError = false;
      output_ << "{\"frame\":" << error.frame << ",\"kind\":";
      writeString(output_, bwgame::health::name_of(error.verdict));
      output_ << ",\"gap\":" << error.gap << '}';
    }
    output_ << "]},\"buildOrders\":{"
            << "\"placed\":" << health.builds_placed
            << ",\"droppedForSupply\":" << health.builds_dropped_supply
            << ",\"droppedForResources\":" << health.builds_dropped_resources
            << ",\"firstDropFrame\":" << health.first_dropped_build_frame
            << ",\"tight\":" << health.builds_tight
            << ",\"placeRejected\":" << health.place_rejected
            << ",\"firstPlaceRejectedFrame\":" << health.first_place_rejected_frame
            << ",\"trainNoSelection\":" << health.train_no_selection
            << ",\"trainCannotBuild\":" << health.train_cannot_build
            << ",\"trainQueueFull\":" << health.train_queue_full
            << ",\"trainUnaffordable\":" << health.train_unaffordable
            << ",\"firstTrainLostFrame\":" << health.first_train_lost_frame
            << ",\"firstTrainNoSelectionFrame\":" << health.first_train_no_selection_frame

            << ",\"minMineralMargin\":" << health.min_mineral_margin
            << ",\"minGasMargin\":" << health.min_gas_margin
            << ",\"dropsTruncated\":"
            << ((health.builds_dropped_supply + health.builds_dropped_resources) > health.dropped_builds.size()
                    ? "true"
                    : "false")
            << ",\"drops\":[";
    bool first = true;
    for (const auto& drop : health.dropped_builds) {
      if (!first) output_ << ',';
      first = false;
      output_ << "{\"frame\":" << drop.frame << ",\"playerId\":";
      const auto playerId = playerIdForSlot_.find(drop.owner);
      if (playerId == playerIdForSlot_.end()) output_ << "null";
      else output_ << playerId->second;
      output_ << ",\"unitType\":";
      writeString(output_, BWAPI::UnitType(drop.unit_type_id).getName());
      output_ << ",\"reason\":";
      writeString(output_, drop.reason == bwgame::health::build_drop::supply ? "supply" : "resources");
      // The balance and the lifetime income behind it. Together they say
      // whether the player was merely late to afford this or never earned it.
      output_ << ",\"minerals\":" << drop.minerals
              << ",\"gas\":" << drop.gas
              << ",\"mineralCost\":" << drop.mineral_cost
              << ",\"gasCost\":" << drop.gas_cost
              << ",\"mineralsGathered\":" << drop.minerals_gathered
              << ",\"gasGathered\":" << drop.gas_gathered;
      output_ << '}';
    }
    output_ << "]},\"replayIntegrity\":{\"traceTruncated\":"
            << (health.integrity_commands_truncated ? "true" : "false")
            << ",\"replaySpeedCommands\":[";
    bool firstReplaySpeed = true;
    for (const auto& command : health.replay_speed_commands) {
      const auto playerId = playerIdForSlot_.find(command.owner);
      if (playerId == playerIdForSlot_.end()) continue;
      if (!firstReplaySpeed) output_ << ',';
      firstReplaySpeed = false;
      output_ << "{\"frame\":" << command.frame << ",\"playerId\":" << playerId->second << '}';
    }
    output_ << "],\"stayInRangeCommands\":";
    writeIntegrityCommandCounts(health.stay_in_range_commands);
    output_ << ",\"cancelMorphCommands\":";
    writeIntegrityCommandCounts(health.cancel_morph_commands);
    output_ << "},\"pools\":[";
    for (std::size_t index = 0; index < (std::size_t)bwgame::health::pool::count; ++index) {
      if (index) output_ << ',';
      const auto& usage = health.pools[index];
      output_ << "{\"name\":";
      writeString(output_, bwgame::health::name_of((bwgame::health::pool)index));
      output_ << ",\"grown\":" << usage.grown
              << ",\"capacity\":" << usage.capacity
              << ",\"refusals\":" << usage.refusals
              << ",\"firstRefusalFrame\":" << usage.first_refusal_frame
              << '}';
    }
    output_ << "],\"damage\":[";
    bool firstDamage = true;
    for (const auto& [key, record] : health.damage) {
      const auto& [weaponId, victimSlot] = key;
      const std::string weapon = weaponName(weaponId);
      const auto victim = playerIdForSlot_.find(victimSlot);
      // Damage to neutral or observer units is real but names no replay player,
      // and attributing it to one would be an invention.
      if (weapon.empty() || victim == playerIdForSlot_.end()) continue;
      if (!firstDamage) output_ << ',';
      firstDamage = false;
      output_ << "{\"weapon\":";
      writeString(output_, weapon);
      output_ << ",\"victimPlayerId\":" << victim->second
              << ",\"damage\":" << record.raw_damage / 256.0
              << ",\"hits\":" << record.hits
              << ",\"kills\":" << record.kills << '}';
    }
    output_ << "]}\n";
  }

  void writeGameResult() {
    const int frame = BWAPI::Broodwar->getFrameCount();
    output_ << "{\"type\":\"gameResult\",\"frame\":" << frame
            << ",\"timestampMs\":" << frame * kFrameDurationMs << ",\"players\":[";
    for (std::size_t index = 0; index < players_.size(); ++index) {
      if (index) output_ << ',';
      const auto player = players_[index];
      const char* result = player->isVictorious() ? "victory"
          : player->isDefeated() ? "defeat"
          : playersWhoLeft_.count(player->getID()) ? "left"
          : "unknown";
      output_ << "{\"playerId\":" << player->getID() << ",\"result\":";
      writeString(output_, result);
      output_ << '}';
    }
    output_ << "]}\n";
  }

  void sample() {
    const int frame = BWAPI::Broodwar->getFrameCount();
    output_ << "{\"type\":\"snapshot\",\"frame\":" << frame
            << ",\"timestampMs\":" << frame * kFrameDurationMs << ",\"players\":[";
    for (std::size_t index = 0; index < players_.size(); ++index) {
      if (index) output_ << ',';
      writePlayerSnapshot(players_[index]);
    }
    output_ << "]}\n";
    writeTerritorySnapshot(frame);
    writeUnitPositionSnapshot(frame);
    lastSampledFrame_ = frame;
  }

  void writePlayerSnapshot(BWAPI::Player player) {
    int workers = 0;
    int mineralWorkers = 0;
    int gasWorkers = 0;
    int idleWorkers = 0;
    int bases = 0;
    int armySupplyDoubled = 0;
    int workerSupplyDoubled = 0;
    int armyMineralValue = 0;
    int armyGasValue = 0;
    std::map<std::string, int> unitCounts;
    std::map<std::string, int> completedUnitCounts;
    std::map<std::string, int> buildingCounts;

    for (auto unit : player->getUnits()) {
      if (!unit || !unit->exists()) continue;
      const auto type = unit->getType();
      ++unitCounts[type.getName()];
      if (unit->isCompleted()) ++completedUnitCounts[type.getName()];
      if (type.isBuilding()) {
        ++buildingCounts[type.getName()];
        if (type.isResourceDepot() && unit->isCompleted()) ++bases;
        continue;
      }
      if (type.isWorker()) {
        ++workers;
        workerSupplyDoubled += type.supplyRequired();
        if (unit->isGatheringMinerals()) ++mineralWorkers;
        else if (unit->isGatheringGas()) ++gasWorkers;
        else if (unit->isIdle()) ++idleWorkers;
        continue;
      }
      if (type.supplyRequired() > 0) {
        armySupplyDoubled += type.supplyRequired();
        armyMineralValue += type.mineralPrice();
        armyGasValue += type.gasPrice();
      }
    }

    std::map<std::string, int> upgrades;
    std::vector<std::string> upgrading;
    for (const auto& upgrade : BWAPI::UpgradeTypes::allUpgradeTypes()) {
      const int level = player->getUpgradeLevel(upgrade);
      if (level > 0) upgrades[upgrade.getName()] = level;
      if (player->isUpgrading(upgrade)) upgrading.push_back(upgrade.getName());
    }
    std::vector<std::string> technologies;
    std::vector<std::string> researching;
    for (const auto& technology : BWAPI::TechTypes::allTechTypes()) {
      if (player->hasResearched(technology)) technologies.push_back(technology.getName());
      else if (player->isResearching(technology)) researching.push_back(technology.getName());
    }

    const double supplyUsed = player->supplyUsed() / 2.0;
    const double workerSupply = workerSupplyDoubled / 2.0;
    const double armySupply = armySupplyDoubled / 2.0;
    const double otherSupply = std::max(0.0, supplyUsed - workerSupply - armySupply);

    output_ << "{\"id\":" << player->getID() << ",\"name\":";
    writeString(output_, player->getName());
    output_ << ",\"race\":";
    writeString(output_, player->getRace().getName());
    output_ << ",\"minerals\":" << player->minerals()
            << ",\"gas\":" << player->gas()
            << ",\"gatheredMinerals\":" << player->gatheredMinerals()
            << ",\"gatheredGas\":" << player->gatheredGas()
            << ",\"spentMinerals\":" << player->spentMinerals()
            << ",\"spentGas\":" << player->spentGas()
            << ",\"supplyUsed\":" << supplyUsed
            << ",\"supplyTotal\":" << player->supplyTotal() / 2.0
            << ",\"workerSupply\":" << workerSupply
            << ",\"armySupply\":" << armySupply
            << ",\"otherSupply\":" << otherSupply
            << ",\"workers\":" << workers
            << ",\"mineralWorkers\":" << mineralWorkers
            << ",\"gasWorkers\":" << gasWorkers
            << ",\"idleWorkers\":" << idleWorkers
            << ",\"bases\":" << bases
            << ",\"armyMineralValue\":" << armyMineralValue
            << ",\"armyGasValue\":" << armyGasValue
            << ",\"unitsLost\":" << unitsLost_[player->getID()]
            << ",\"unitsKilled\":" << unitsKilled_[player->getID()]
            << ",\"enemySideArmySupply\":" << enemySideSupplyDoubled_[player->getID()] / 2.0
            << ",\"unitCounts\":";
    writeCountMap(output_, unitCounts);
    output_ << ",\"completedUnitCounts\":";
    writeCountMap(output_, completedUnitCounts);
    output_ << ",\"buildingCounts\":";
    writeCountMap(output_, buildingCounts);
    output_ << ",\"upgrades\":";
    writeCountMap(output_, upgrades);
    output_ << ",\"upgrading\":[";
    for (std::size_t index = 0; index < upgrading.size(); ++index) {
      if (index) output_ << ',';
      writeString(output_, upgrading[index]);
    }
    output_ << "],\"technologies\":[";
    for (std::size_t index = 0; index < technologies.size(); ++index) {
      if (index) output_ << ',';
      writeString(output_, technologies[index]);
    }
    output_ << "],\"researching\":[";
    for (std::size_t index = 0; index < researching.size(); ++index) {
      if (index) output_ << ',';
      writeString(output_, researching[index]);
    }
    output_ << "]}";
  }

  std::string outputPath_;
  int intervalFrames_;
  bool effectScan_ = false;
  int lastSampledFrame_ = -1;
  int lastUnitPositionFrame_ = -1;
  bool completed_ = false;
  std::ofstream output_;
  std::vector<BWAPI::Player> players_;
  std::vector<BaseSite> baseSites_;
  std::map<int, int> playerIdForSlot_;
  std::map<int, BWAPI::Position> playerStarts_;
  std::set<int> seenUnits_;
  std::map<int, std::string> unitTypes_;
  std::map<int, int> unitOwners_;
  std::map<int, int> unitTransports_;
  std::map<int, bool> unitEnemySide_;
  std::map<int, std::set<std::string>> unitStatuses_;
  std::map<int, int> bwapiIdForOpenBwIndex_;
  std::map<long long, int> bwapiIdForOpenBwUnit_;
  std::map<int, int> enemySideSupplyDoubled_;
  std::map<int, int> unitsLost_;
  std::map<int, int> unitsKilled_;
  std::set<int> playersWhoLeft_;
};

struct Arguments {
  std::string replayPath;
  std::string outputPath;
  int intervalFrames = 24;

};

Arguments parseArguments(int argc, char** argv) {
  Arguments arguments;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--replay" && index + 1 < argc) arguments.replayPath = argv[++index];
    else if (argument == "--output" && index + 1 < argc) arguments.outputPath = argv[++index];
    else if (argument == "--interval-frames" && index + 1 < argc) {
      const std::string value = argv[++index];
      std::size_t consumed = 0;
      arguments.intervalFrames = std::stoi(value, &consumed);
      if (consumed != value.size()) throw std::runtime_error("invalid interval frames");
    }
    else throw std::runtime_error("unknown or incomplete argument: " + argument);
  }
  if (arguments.replayPath.empty() || arguments.outputPath.empty()) {
    throw std::runtime_error("usage: sb-replay-analyzer --replay FILE.rep --output FILE.ndjson "
                             "[--interval-frames 24]");
  }
  if (arguments.intervalFrames < 1 || arguments.intervalFrames > 1440) {
    throw std::runtime_error("interval frames must be between 1 and 1440");
  }
  return arguments;
}

void validateInputs(const Arguments& arguments) {
  namespace fs = std::filesystem;
  if (!fs::is_regular_file(arguments.replayPath)) {
    throw std::runtime_error("replay file does not exist");
  }
  if (fs::weakly_canonical(arguments.replayPath) == fs::weakly_canonical(arguments.outputPath)
      || (fs::exists(arguments.outputPath) && fs::equivalent(arguments.replayPath, arguments.outputPath))) {
    throw std::runtime_error("output must not overwrite the replay");
  }
  const char* mpq = std::getenv("OPENBW_MPQ_PATH");
  const char* overrides = std::getenv("OPENBW_OVERRIDE_PATH");
  if (!mpq || !*mpq || !overrides || !*overrides) {
    throw std::runtime_error("set OPENBW_MPQ_PATH and OPENBW_OVERRIDE_PATH to local StarCraft data");
  }
  for (const auto* archive : {"StarDat.mpq", "BrooDat.mpq", "Patch_rt.mpq"}) {
    const auto path = fs::path(mpq) / archive;
    if (!fs::is_regular_file(path) || fs::file_size(path) == 0) {
      throw std::runtime_error(std::string("missing or empty game archive: ") + archive);
    }
  }
  // Classic tilesets can load a modern map with silently corrupted terrain.
  for (const auto* tileset : {"badlands", "platform", "install", "ashworld", "jungle", "Desert", "Ice", "Twilight"}) {
    for (const auto* extension : {".cv5", ".vf4"}) {
      const std::string name = std::string(tileset) + extension;
      const auto flat = fs::path(overrides) / name;
      const auto nested = fs::path(overrides) / "Tileset" / name;
      if ((!fs::is_regular_file(flat) || fs::file_size(flat) == 0)
          && (!fs::is_regular_file(nested) || fs::file_size(nested) == 0)) {
        throw std::runtime_error("missing or empty Remastered tileset: " + name);
      }
    }
  }
}

void setEnvironment(const char* name, const std::string& value) {
#ifdef _WIN32
  _putenv_s(name, value.c_str());
#else
  setenv(name, value.c_str(), 1);
#endif
}

}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc == 2 && std::string(argv[1]) == "--help") {
      std::cout << "usage: sb-replay-analyzer --replay FILE.rep --output FILE.ndjson "
                   "[--interval-frames 24]\n";
      return 0;
    }
    if (argc == 2 && std::string(argv[1]) == "--version") {
      std::cout << "sb-replay-analyzer 0.1.0 " << kBackendVersion << '\n';
      return 0;
    }
    const auto arguments = parseArguments(argc, argv);
    validateInputs(arguments);
    setEnvironment("OPENBW_ENABLE_UI", "0");
    setEnvironment("OPENBW_GAME_SPEED", "0");
#ifdef __EMSCRIPTEN__
    setEnvironment("OPENBW_MPQ_PATH", "/openbw-runtime");
    setEnvironment("OPENBW_OVERRIDE_PATH", "/openbw-runtime");
#endif
    setEnvironment("BWAPI_CONFIG_AUTO_MENU__AUTO_MENU", "SINGLE_PLAYER");
    setEnvironment("BWAPI_CONFIG_AUTO_MENU__MAP", arguments.replayPath);
    applyProcessSandbox();

    int result = 0;
    BW::sacrificeThreadForUI([&] {
      try {
        BW::GameOwner gameOwner;
        gameOwner.setPrintTextCallback([](const char* text) {
          if (text && *text) std::cerr << text << '\n';
        });
        BWAPI::BroodwarImpl_handle handle(gameOwner.getGame());
        SnapshotModule snapshotModule(arguments.outputPath, arguments.intervalFrames);
        handle->setAIModule(&snapshotModule);
        handle->autoMenuManager.startGame();
        while (!handle->bwgame.gameOver()) {
          handle->update();
          handle->bwgame.nextFrame();
        }
        handle->update();
        handle->onGameEnd();
        handle->bwgame.leaveGame();
      } catch (const std::exception& error) {
        std::cerr << "simulation error: " << error.what() << '\n';
        result = 1;
      }
    });
    return result;
  } catch (const std::exception& error) {
    std::cerr << "argument error: " << error.what() << '\n';
    return 2;
  }
}
