#ifndef __DEBUG_H
#define __DEBUG_H

#ifndef DEBUG
#define debug(...)
#else
#define debug(...) do { \
          printf("[DEBUG (%s)] %s: ", __FILE__, __FUNCTION__); \
          printf(__VA_ARGS__); \
          printf("\n"); \
      } while (0)
#endif

#endif
