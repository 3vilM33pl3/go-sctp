#include <arpa/inet.h>
#include <linux/sctp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {

[[noreturn]] void die(const std::string& msg) {
  std::cerr << "error: " << msg << ": " << std::strerror(errno) << "\n";
  std::exit(1);
}

std::vector<std::string> parse_hosts(const std::string& in) {
  std::vector<std::string> out;
  std::size_t start = 0;
  while (start <= in.size()) {
    std::size_t end = in.find(',', start);
    std::string part = in.substr(start, end == std::string::npos ? std::string::npos : end - start);
    if (!part.empty()) out.push_back(part);
    if (end == std::string::npos) break;
    start = end + 1;
  }
  if (out.empty()) out.push_back("127.0.0.1");
  return out;
}

sockaddr_in mk_addr(const std::string& host, int port) {
  sockaddr_in out{};
  out.sin_family = AF_INET;
  out.sin_port = htons(static_cast<uint16_t>(port));
  if (inet_pton(AF_INET, host.c_str(), &out.sin_addr) != 1) {
    std::cerr << "error: invalid IPv4 address: " << host << "\n";
    std::exit(1);
  }
  return out;
}

void connectx_if_multihome(int fd, const std::vector<sockaddr_in>& addrs) {
  if (addrs.size() <= 1) return;
  std::vector<unsigned char> packed(sizeof(sockaddr_in) * addrs.size());
  std::memcpy(packed.data(), addrs.data(), packed.size());
  int rc = setsockopt(fd, IPPROTO_SCTP, SCTP_SOCKOPT_CONNECTX, packed.data(), static_cast<socklen_t>(packed.size()));
  if (rc >= 0 || errno == EINPROGRESS || errno == EALREADY) {
    return;
  }
  if (errno != ENOPROTOOPT) {
    die("setsockopt(SCTP_SOCKOPT_CONNECTX)");
  }
  rc = setsockopt(fd, IPPROTO_SCTP, SCTP_SOCKOPT_CONNECTX_OLD, packed.data(), static_cast<socklen_t>(packed.size()));
  if (rc < 0 && errno != EINPROGRESS && errno != EALREADY) {
    die("setsockopt(SCTP_SOCKOPT_CONNECTX_OLD)");
  }
}

}  // namespace

int main(int argc, char** argv) {
  std::string server_hosts = "127.0.0.1";
  int server_port = 19000;
  std::string payload = "hello-from-cpp";
  uint16_t stream = 1;
  uint32_t ppid = 42;

  if (argc > 1) server_hosts = argv[1];
  if (argc > 2) server_port = std::stoi(argv[2]);
  if (argc > 3) payload = argv[3];
  if (argc > 4) stream = static_cast<uint16_t>(std::stoi(argv[4]));
  if (argc > 5) ppid = static_cast<uint32_t>(std::stoul(argv[5]));

  int fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
  if (fd < 0) die("socket");

  std::vector<std::string> hosts = parse_hosts(server_hosts);
  std::vector<sockaddr_in> dsts;
  dsts.reserve(hosts.size());
  for (const auto& h : hosts) dsts.push_back(mk_addr(h, server_port));
  connectx_if_multihome(fd, dsts);
  sockaddr_in dst = dsts.front();

  iovec iov{};
  iov.iov_base = const_cast<char*>(payload.data());
  iov.iov_len = payload.size();

  char cbuf[CMSG_SPACE(sizeof(sctp_sndinfo))]{};
  msghdr msg{};
  msg.msg_name = &dst;
  msg.msg_namelen = sizeof(dst);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cbuf;
  msg.msg_controllen = sizeof(cbuf);

  cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = IPPROTO_SCTP;
  cmsg->cmsg_type = SCTP_SNDINFO;
  cmsg->cmsg_len = CMSG_LEN(sizeof(sctp_sndinfo));

  auto* snd = reinterpret_cast<sctp_sndinfo*>(CMSG_DATA(cmsg));
  std::memset(snd, 0, sizeof(*snd));
  snd->snd_sid = stream;
  snd->snd_ppid = ppid;

  int n = sendmsg(fd, &msg, 0);
  if (n < 0) die("sendmsg");

  std::cout << "CPP_CLIENT_SENT stream=" << stream << " ppid=" << ppid << " payload=" << payload << "\n";
  close(fd);
  return 0;
}
