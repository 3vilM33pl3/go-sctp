#include <arpa/inet.h>
#include <linux/sctp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <chrono>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

constexpr uint8_t kFrameData = 1;
constexpr uint8_t kFrameStop = 2;
constexpr uint8_t kFrameResult = 3;
constexpr uint32_t kDefaultPpid = 0x50524631;  // "PRF1"

[[noreturn]] void die(const std::string& msg) {
  std::cerr << "error: " << msg << ": " << std::strerror(errno) << "\n";
  std::exit(1);
}

sockaddr_in parse_addr(const std::string& host, int port) {
  sockaddr_in out{};
  out.sin_family = AF_INET;
  out.sin_port = htons(static_cast<uint16_t>(port));
  if (inet_pton(AF_INET, host.c_str(), &out.sin_addr) != 1) {
    std::cerr << "error: invalid IPv4 address: " << host << "\n";
    std::exit(1);
  }
  return out;
}

void set_basic_opts(int fd) {
  int on = 1;
  if (setsockopt(fd, IPPROTO_SCTP, SCTP_RECVRCVINFO, &on, sizeof(on)) < 0) {
    die("setsockopt(SCTP_RECVRCVINFO)");
  }
  timeval tv{};
  tv.tv_sec = 20;
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    die("setsockopt(SO_RCVTIMEO)");
  }
  if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
    die("setsockopt(SO_SNDTIMEO)");
  }
}

std::vector<uint8_t> encode_frame(uint8_t kind, const std::vector<uint8_t>& payload) {
  std::vector<uint8_t> out(5 + payload.size());
  out[0] = kind;
  const uint32_t be = htonl(static_cast<uint32_t>(payload.size()));
  std::memcpy(out.data() + 1, &be, sizeof(be));
  if (!payload.empty()) {
    std::memcpy(out.data() + 5, payload.data(), payload.size());
  }
  return out;
}

bool decode_frame(const std::vector<uint8_t>& in, uint8_t* kind, std::vector<uint8_t>* payload) {
  if (in.size() < 5) return false;
  uint32_t be_size = 0;
  std::memcpy(&be_size, in.data() + 1, sizeof(be_size));
  uint32_t payload_size = ntohl(be_size);
  if (in.size() != 5 + payload_size) return false;
  *kind = in[0];
  payload->assign(in.begin() + 5, in.end());
  return true;
}

struct RecvPacket {
  bool notification = false;
  sockaddr_in src{};
  bool has_rcvinfo = false;
  sctp_rcvinfo rcvinfo{};
  uint8_t kind = 0;
  std::vector<uint8_t> payload;
};

RecvPacket recv_packet(int fd, size_t max_payload_size) {
  RecvPacket pkt{};
  std::vector<uint8_t> frame_buf(max_payload_size + 5);
  char cbuf[CMSG_SPACE(sizeof(sctp_rcvinfo))]{};

  iovec iov{};
  iov.iov_base = frame_buf.data();
  iov.iov_len = frame_buf.size();

  msghdr msg{};
  msg.msg_name = &pkt.src;
  msg.msg_namelen = sizeof(pkt.src);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cbuf;
  msg.msg_controllen = sizeof(cbuf);

  const ssize_t n = recvmsg(fd, &msg, 0);
  if (n < 0) die("recvmsg");
  if (n == 0) die("recvmsg EOF");
  if ((msg.msg_flags & MSG_TRUNC) != 0) {
    die("received truncated frame");
  }
  if ((msg.msg_flags & MSG_NOTIFICATION) != 0) {
    pkt.notification = true;
    return pkt;
  }

  for (cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level == IPPROTO_SCTP && cmsg->cmsg_type == SCTP_RCVINFO) {
      auto* rcv = reinterpret_cast<sctp_rcvinfo*>(CMSG_DATA(cmsg));
      pkt.rcvinfo = *rcv;
      pkt.has_rcvinfo = true;
    }
  }

  frame_buf.resize(static_cast<size_t>(n));
  if (!decode_frame(frame_buf, &pkt.kind, &pkt.payload)) {
    std::cerr << "error: malformed frame\n";
    std::exit(1);
  }
  return pkt;
}

void send_packet(int fd, const sockaddr_in& dst, const sctp_sndinfo& sndinfo, uint8_t kind,
                 const std::vector<uint8_t>& payload) {
  std::vector<uint8_t> frame = encode_frame(kind, payload);
  iovec iov{};
  iov.iov_base = frame.data();
  iov.iov_len = frame.size();

  char cbuf[CMSG_SPACE(sizeof(sctp_sndinfo))]{};
  msghdr msg{};
  msg.msg_name = const_cast<sockaddr_in*>(&dst);
  msg.msg_namelen = sizeof(dst);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cbuf;
  msg.msg_controllen = sizeof(cbuf);

  cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = IPPROTO_SCTP;
  cmsg->cmsg_type = SCTP_SNDINFO;
  cmsg->cmsg_len = CMSG_LEN(sizeof(sctp_sndinfo));
  std::memcpy(CMSG_DATA(cmsg), &sndinfo, sizeof(sndinfo));

  if (sendmsg(fd, &msg, 0) < 0) {
    die("sendmsg");
  }
}

}  // namespace

int main(int argc, char** argv) {
  std::signal(SIGPIPE, SIG_IGN);

  std::string host = "127.0.0.1";
  int port = 19100;
  std::string mode = "rtt";
  int iterations = 200;
  int payload_size = 256;

  if (argc > 1) host = argv[1];
  if (argc > 2) port = std::stoi(argv[2]);
  if (argc > 3) mode = argv[3];
  if (argc > 4) iterations = std::stoi(argv[4]);
  if (argc > 5) payload_size = std::stoi(argv[5]);
  if (mode != "rtt" && mode != "throughput") {
    std::cerr << "error: invalid mode " << mode << " (expected rtt|throughput)\n";
    return 1;
  }
  if (iterations <= 0 || payload_size <= 0) {
    std::cerr << "error: iterations and payload size must be positive\n";
    return 1;
  }

  int fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
  if (fd < 0) die("socket");
  set_basic_opts(fd);

  sockaddr_in bind_addr = parse_addr(host, port);
  if (bind(fd, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) < 0) {
    die("bind");
  }
  if (listen(fd, 128) < 0) {
    die("listen");
  }

  std::cout << "PERF_SERVER_READY lang=cpp mode=" << mode << " bind=" << host << ":" << port
            << " iterations=" << iterations << " size=" << payload_size << "\n";

  size_t msgs = 0;
  size_t bytes = 0;
  bool started = false;
  auto start = std::chrono::steady_clock::now();

  for (;;) {
    RecvPacket pkt = recv_packet(fd, static_cast<size_t>(payload_size) + 4096);
    if (pkt.notification) continue;

    if (mode == "rtt") {
      if (pkt.kind != kFrameData) {
        std::cerr << "error: unexpected frame kind in rtt mode: " << static_cast<int>(pkt.kind) << "\n";
        close(fd);
        return 1;
      }
      if (!started) {
        start = std::chrono::steady_clock::now();
        started = true;
      }
      msgs++;
      bytes += pkt.payload.size();

      sctp_sndinfo snd{};
      snd.snd_sid = pkt.has_rcvinfo ? pkt.rcvinfo.rcv_sid : 0;
      snd.snd_ppid = pkt.has_rcvinfo ? pkt.rcvinfo.rcv_ppid : kDefaultPpid;
      snd.snd_assoc_id = pkt.has_rcvinfo ? pkt.rcvinfo.rcv_assoc_id : 0;
      send_packet(fd, pkt.src, snd, kFrameData, pkt.payload);

      if (static_cast<int>(msgs) >= iterations) {
        break;
      }
      continue;
    }

    if (pkt.kind == kFrameData) {
      if (!started) {
        start = std::chrono::steady_clock::now();
        started = true;
      }
      msgs++;
      bytes += pkt.payload.size();
      continue;
    }
    if (pkt.kind != kFrameStop) {
      std::cerr << "error: unexpected frame kind in throughput mode: " << static_cast<int>(pkt.kind) << "\n";
      close(fd);
      return 1;
    }

    const auto end = std::chrono::steady_clock::now();
    const double seconds = std::chrono::duration<double>(end - start).count();
    std::ostringstream oss;
    oss << "messages=" << msgs << " bytes=" << bytes << " seconds=" << seconds;
    std::string result = oss.str();
    std::vector<uint8_t> payload(result.begin(), result.end());
    sctp_sndinfo snd{};
    snd.snd_sid = pkt.has_rcvinfo ? pkt.rcvinfo.rcv_sid : 0;
    snd.snd_ppid = pkt.has_rcvinfo ? pkt.rcvinfo.rcv_ppid : kDefaultPpid;
    snd.snd_assoc_id = pkt.has_rcvinfo ? pkt.rcvinfo.rcv_assoc_id : 0;
    send_packet(fd, pkt.src, snd, kFrameResult, payload);
    break;
  }

  const auto end = std::chrono::steady_clock::now();
  const double seconds = std::chrono::duration<double>(end - start).count();
  std::cout << "PERF_SERVER_DONE lang=cpp mode=" << mode << " messages=" << msgs << " bytes=" << bytes
            << " seconds=" << seconds << "\n";
  close(fd);
  return 0;
}
