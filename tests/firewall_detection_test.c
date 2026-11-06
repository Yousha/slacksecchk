#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

/* Include the implementation to exercise the private ruleset parsers. */
#include "../src/rules.c"

static int write_command(const char *directory, const char *name, const char *body) {
   char path[512];
   FILE *file;
   if (snprintf(path, sizeof(path), "%s/%s", directory, name) >= (int)sizeof(path))
      return 0;
   file = fopen(path, "w");
   if (file == NULL) return 0;
   fputs("#!/bin/sh\n", file);
   fputs(body, file);
   fclose(file);
   return chmod(path, 0700) == 0;
}

static int expect(int condition, const char *message) {
   if (!condition) {
      fprintf(stderr, "FAIL: %s\n", message);
      return 0;
   }
   printf("PASS: %s\n", message);
   return 1;
}

int main(void) {
   char directory[] = "/tmp/slacksecchk-fwtest-XXXXXX";
   char path[1024];
   int passed = 1;

   if (mkdtemp(directory) == NULL) {
      perror("mkdtemp");
      return 2;
   }
   if (snprintf(path, sizeof(path), "%s:/usr/bin:/bin", directory) >= (int)sizeof(path) ||
       setenv("PATH", path, 1) != 0) {
      perror("setenv");
      return 2;
   }

   passed &= expect(write_command(directory, "iptables-save",
      "cat <<'EOF'\n:INPUT DROP [0:0]\n:FORWARD ACCEPT [0:0]\nCOMMIT\nEOF\n"),
      "create iptables fixture");
   passed &= expect(iptables_filter_is_active("iptables-save"),
      "iptables default DROP policy is detected");

   passed &= expect(write_command(directory, "iptables-save",
      "cat <<'EOF'\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\nCOMMIT\nEOF\n"),
      "replace iptables fixture");
   passed &= expect(!iptables_filter_is_active("iptables-save"),
      "ACCEPT-only iptables policies are not treated as an active firewall");

   passed &= expect(write_command(directory, "iptables-save",
      "cat <<'EOF'\n:INPUT ACCEPT [0:0]\n-A INPUT -p tcp -j DROP\nCOMMIT\nEOF\n"),
      "replace iptables rule fixture");
   passed &= expect(iptables_filter_is_active("iptables-save"),
      "explicit iptables DROP rules are detected");

   passed &= expect(write_command(directory, "iptables-save",
      "cat <<'EOF'\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n-A FORWARD -p tcp -j REJECT\nCOMMIT\nEOF\n"),
      "replace iptables FORWARD rule fixture");
   passed &= expect(iptables_filter_is_active("iptables-save"),
      "explicit iptables FORWARD REJECT rules are detected");

   passed &= expect(write_command(directory, "nft",
      "cat <<'EOF'\ntable inet filter {\n chain input {\n  type filter hook input priority filter; policy drop;\n }\n}\nEOF\n"),
      "create nftables fixture");
   passed &= expect(nft_filter_is_active(),
      "nftables input-chain DROP policy is detected");

   passed &= expect(write_command(directory, "nft",
      "cat <<'EOF'\ntable inet filter {\n chain input {\n  type filter hook input priority filter; policy accept;\n }\n}\nEOF\n"),
      "replace nftables fixture");
   passed &= expect(!nft_filter_is_active(),
      "ACCEPT-only nftables policy is not treated as an active firewall");

   snprintf(path, sizeof(path), "%s/iptables-save", directory);
   unlink(path);
   snprintf(path, sizeof(path), "%s/nft", directory);
   unlink(path);
   rmdir(directory);

   return passed ? 0 : 1;
}
