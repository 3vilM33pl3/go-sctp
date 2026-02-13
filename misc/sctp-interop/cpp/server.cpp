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

void set_basic_opts(int fd) {
  int on = 1;
  if (setsockopt(fd, IPPROTO_SCTP, SCTP_RECVRCVINFO, &on, sizeof(on)) < 0) {
    die("setsockopt(SCTP_RECVRCVINFO)");
  }

  sctp_event ev{};
  ev.se_assoc_id = SCTP_FUTURE_ASSOC;

  const uint16_t event_types[] = {
      SCTP_ASSOC_CHANGE,
      SCTP_SHUTDOWN_EVENT,
      SCTP_DATA_IO_EVENT,
  };

  for (uint16_t typ : event_types) {
    ev.se_type = typ;
    ev.se_on = 1;
    if (setsockopt(fd, IPPROTO_SCTP, SCTP_EVENT, &ev, sizeof(ev)) < 0) {
      die("setsockopt(SCTP_EVENT)");
    }
  }
}

}  // namespace

int main(int argc, char** argv) {
  const char* bind_ip = "127.0.0.1";
  int bind_port = 19001;

  if (argc > 1) bind_ip = argv[1];
  if (argc > 2) bind_port = std::stoi(argv[2]);

  int fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
  if (fd < 0) die("socket");

  set_basic_opts(fd);

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(bind_port));
  if (inet_pton(AF_INET, bind_ip, &addr.sin_addr) != 1) {
    std::cerr << "error: invalid IPv4 address\n";
    return 1;
  }

  if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    die("bind");
  }
  if (listen(fd, 128) < 0) {
    die("listen");
  }

  for (;;) {
    char data[2048]{};
    char cbuf[CMSG_SPACE(sizeof(sctp_rcvinfo))]{};

    iovec iov{};
    iov.iov_base = data;
    iov.iov_len = sizeof(data);

    sockaddr_in src{};
    msghdr msg{};
    msg.msg_name = &src;
    msg.msg_namelen = sizeof(src);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    ssize_t n = recvmsg(fd, &msg, 0);
    if (n < 0) die("recvmsg");

    if ((msg.msg_flags & MSG_NOTIFICATION) != 0) {
      auto* sn = reinterpret_cast<sctp_notification*>(data);
      std::cout << "CPP_NOTIFY type=" << sn->sn_header.sn_type << "\n";
      continue;
    }

    uint16_t stream = 0;
    uint32_t ppid = 0;
    for (cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
      if (cmsg->cmsg_level == IPPROTO_SCTP && cmsg->cmsg_type == SCTP_RCVINFO) {
        auto* rcv = reinterpret_cast<sctp_rcvinfo*>(CMSG_DATA(cmsg));
        stream = rcv->rcv_sid;
        ppid = rcv->rcv_ppid;
      }
    }

    std::string payload(data, data + n);
    std::cout << "CPP_SERVER_RECV stream=" << stream << " ppid=" << ppid << " payload=" << payload << "\n";
    close(fd);
    return 0;
  }
}
