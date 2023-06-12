#ifndef __BLOOM_FILTER_NEW_H__
#define __BLOOM_FILTER_NEW_H__

#include <cassert>
#include <bitset>
#include <vector>
#include <cstdlib>
#include <cmath>
#include <ctime>
#include <iostream>

using namespace std;

#define RAND_SEED 29346
#define MAX_BITS 16384
#define BF_SIZE 65536
#define NUM_HASH_FUNC 4


class h3_bloom_filter_t {
  protected:

  uint16_t seed;
  uint16_t nth;
  uint32_t nbf2;

  uint32_t cnt_arr[BF_SIZE];
  uint32_t hashed_addr[NUM_HASH_FUNC]; //> hashed_addr;

  int bf_size;

  public:
  uint32_t cumulative_count;

  h3_bloom_filter_t()
  {
  }

  void initialize(int bf_size, uint16_t nth, uint32_t nbf2, uint32_t rand_seed);

  uint32_t count();

  void clear();

  void apply_hash_function(uint16_t row_addr);

  int insert(uint16_t row_addr);

  bool test(uint16_t row_addr);

  int get_act_cnt(uint16_t row_addr);
};


#endif
