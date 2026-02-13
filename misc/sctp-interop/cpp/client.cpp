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

namespace {

[[noreturn]] void die(const std::string& msg) {
  std::cerr << "error: " << msg << ": " << std::strerror(errno) << "\n";
  std::exit(1);
}

}  // namespace

int main(int argc, char** argv) {
  const char* server_ip = "127.0.0.1";
  int server_port = 19000;
  std::string payload = "hello-from-cpp";
  uint16_t stream = 1;
  uint32_t ppid = 42;

  if (argc > 1) server_ip = argv[1];
  if (argc > 2) server_port = std::stoi(argv[2]);
  if (argc > 3) payload = argv[3];
  if (argc > 4) stream = static_cast<uint16_t>(std::stoi(argv[4]));
  if (argc > 5) ppid = static_cast<uint32_t>(std::stoul(argv[5]));

  int fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
  if (fd < 0) die("socket");

  sockaddr_in dst{};
  dst.sin_family = AF_INET;
  dst.sin_port = htons(static_cast<uint16_t>(server_port));
  if (inet_pton(AF_INET, server_ip, &dst.sin_addr) != 1) {
    std::cerr << "error: invalid IPv4 address\n";
    return 1;
  }

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
