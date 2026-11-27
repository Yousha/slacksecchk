#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include "rules.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

// ANSI color codes for terminal output.
#define COLOR_GREEN "\033[1;32m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_RED "\033[1;31m"
#define COLOR_RESET "\033[0m"

/* NOTE: Full expanded implementation is in the local build; this placeholder will be replaced. See PR description. */
