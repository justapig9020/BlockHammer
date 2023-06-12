#include "BloomFilter.h"

void h3_bloom_filter_t::initialize(int bf_size, uint16_t nth, uint32_t nbf2, uint32_t rand_seed)
{
  this->bf_size = bf_size;
  this->nth = nth;
  this->nbf2 = nbf2;

  srand(rand_seed);
  clear();
}

uint32_t h3_bloom_filter_t::count(){
  return cumulative_count;
}

void h3_bloom_filter_t::clear(){
  seed = rand() % bf_size;
  for (int i = 0 ; i < bf_size ; i++){
    cnt_arr[i] = 0;
  }
  cumulative_count = 0;
}

void h3_bloom_filter_t::apply_hash_function(uint16_t row_addr){
  if (bf_size <= 1024){
    /*|----Selecting the bits for hash functions - 1024 counters---|
     *|RowID | 15 14 13 12 | 11 10  9  8 | 7  6  5  4 | 3  2  1  0 |
     *|Counts|  3  3  3  3 |  3  3  3  3 | 3  3  2  2 | 2  2  1  1 |
     *|------|-----------------------------------------------------|
     *|BL #0 |  9  8  7  6 |  5  4  3  2 | 1  0       |            |
     *|BL #1 |     9  8  7 |  6  5  4  3 | 2  1  0    |            |
     *|BL #2 |  3  2  1  0 |             | 9  8  7  6 | 5  4       |
     *|BL #3 |  1  0     9 |  8  7  6  5 | 4     3  2 |            |
     *|------------------------------------------------------------|
     */
    hashed_addr[0] = (row_addr >> 6) & 0x03FF;
    hashed_addr[1] = (row_addr >> 5) & 0x03FF;
    hashed_addr[2] = ((row_addr >> 12) & 0x000F)
      | ((row_addr << 2)  & 0x03F0);
    hashed_addr[3] = ((row_addr >> 14) & 0x0003)
      | ((row_addr >>  2) & 0x000C)
      | ((row_addr >>  3) & 0x01F0);
  }
  else if (bf_size <= 2048){
    /*|----Selecting the bits for hash functions - 2048 counters---|
     *|RowID | 15 14 13 12 | 11 10  9  8 | 7  6  5  4 | 3  2  1  0 |
     *|Counts|  3  3  3  3 |  3  3  3  3 | 3  3  3  3 | 2  2  2  2 |
     *|------|-----------------------------------------------------|
     *|BL #1 | 10  9  8  7 |  6  5  4  3 | 2  1  0    |            |
     *|BL #2 |             |    10  9  8 | 7  6  5  4 | 3  2  1  0 |
     *|BL #3 |  5  4  3  2 |  1  0       |         10 | 9  8  7  6 |
     *|BL #4 |  4  3  2  1 |  0    10  9 | 8  7  6  5 |            |
     *|------------------------------------------------------------|
     */
    hashed_addr[0] = (row_addr >> 5) & 0x07FF;
    hashed_addr[1] = (row_addr     ) & 0x07FF;
    hashed_addr[2] = ((row_addr >> 10) & 0x003F)
      | ((row_addr <<  6) & 0x07C0);
    hashed_addr[3] = ((row_addr >> 11) & 0x001F)
      | ((row_addr <<  1) & 0x07E0);
  }
  else if (bf_size <= 4096){
    /*|----Selecting the bits for hash functions - 4096 counters-----|
     *|RowID | 15 14 13 12 | 11 10  9  8 |  7  6  5  4 |  3  2  1  0 |
     *|Counts|  3  3  3  3 |  3  3  3  3 |  3  3  3  3 |  3  3  3  3 |
     *|------|-------------------------------------------------------|
     *|BL #1 | 11 10  9  8 |  7  6  5  4 |  3  2  1  0 |             |
     *|BL #2 |             | 11 10  9  8 |  7  6  5  4 |  3  2  1  0 |
     *|BL #3 |  7  6  5  4 |  3  2  1  0 |             | 11 10  9  8 |
     *|BL #4 |  3  2  1  0 |             | 11 10  9  8 |  7  6  5  4 |
     *|--------------------------------------------------------------|
     */
    hashed_addr[0] = (row_addr >> 4) & 0x0FFF;
    hashed_addr[1] = (row_addr     ) & 0x0FFF;
    hashed_addr[2] = ((row_addr >>  8) & 0x00FF)
      | ((row_addr <<  8) & 0x0F00);
    hashed_addr[3] = ((row_addr >> 12) & 0x000F)
      | ((row_addr <<  4) & 0x0FF0);
  }
  else if (bf_size <= 8192){
    /*|----Selecting the bits for hash functions - 8192  counters----|
     *|RowID | 15 14 13 12 | 11 10  9  8 |  7  6  5  4 |  3  2  1  0 |
     *|Counts|  3  3  3  3 |  3  3  3  3 |  3  3  3  3 |  3  3  3  3 |
     *|------|-------------------------------------------------------|
     *|BL #1 |          12 | 11 10  9  8 |  7  6  5  4 |  3  2  1  0 |
     *|BL #2 |  3  2  1  0 |          12 | 11 10  9  8 |  7  6  5  4 |
     *|BL #3 |  7  6  5  4 |  3  2  1  0 |          12 | 11 10  9  8 |
     *|BL #4 | 11 10  9  8 |  7  6  5  4 |  3  2  1  0 |          12 |
     *|--------------------------------------------------------------|
     */
    hashed_addr[0] = row_addr & 0x1FFF;
    hashed_addr[1] = ((row_addr <<  4) & 0x1FF0)
      | ((row_addr >> 12) & 0x000F);
    hashed_addr[2] = ((row_addr >>  8) & 0x00FF)
      | ((row_addr <<  8) & 0x1F00);
    hashed_addr[3] = ((row_addr << 12) & 0x1000)
      | ((row_addr >>  4) & 0x0FFF);
  }
  else if (bf_size <= 16384){
    /*|----Selecting the bits for hash functions - 8192  counters----|
     *|RowID | 15 14 13 12 | 11 10  9  8 |  7  6  5  4 |  3  2  1  0 |
     *|Counts|  3  3  3  3 |  3  3  3  3 |  3  3  3  3 |  3  3  3  3 |
     *|------|-------------------------------------------------------|
     *|BL #1 |       13 12 | 11 10  9  8 |  7  6  5  4 |  3  2  1  0 |
     *|BL #2 |  3  2  1  0 |       13 12 | 11 10  9  8 |  7  6  5  4 |
     *|BL #3 |  7  6  5  4 |  3  2  1  0 |       13 12 | 11 10  9  8 |
     *|BL #4 | 11 10  9  8 |  7  6  5  4 |  3  2  1  0 |       13 12 |
     *|--------------------------------------------------------------|
     */
    hashed_addr[0] = row_addr & 0x3FFF;
    hashed_addr[1] = ((row_addr <<  4) & 0x3FF0)
      | ((row_addr >> 12) & 0x000F);
    hashed_addr[2] = ((row_addr >>  8) & 0x00FF)
      | ((row_addr <<  8) & 0x3F00);
    hashed_addr[3] = ((row_addr >>  4) & 0x0FFF)
      | ((row_addr << 12) & 0x3000);
  }
  else if (bf_size <= 32768){
    /*|----Selecting the bits for hash functions - 8192  counters----|
     *|RowID | 15 14 13 12 | 11 10  9  8 |  7  6  5  4 |  3  2  1  0 |
     *|Counts|  3  3  3  3 |  3  3  3  3 |  3  3  3  3 |  3  3  3  3 |
     *|------|-------------------------------------------------------|
     *|BL #1 |    14 13 12 | 11 10  9  8 |  7  6  5  4 |  3  2  1  0 |
     *|BL #2 |  3  2  1  0 |    14 13 12 | 11 10  9  8 |  7  6  5  4 |
     *|BL #3 |  7  6  5  4 |  3  2  1  0 |    14 13 12 | 11 10  9  8 |
     *|BL #4 | 11 10  9  8 |  7  6  5  4 |  3  2  1  0 |    14 13 12 |
     *|--------------------------------------------------------------|
     */
    hashed_addr[0] = row_addr & 0x7FFF;
    hashed_addr[1] = ((row_addr <<  4) & 0x7FF0)
      | ((row_addr >> 12) & 0x000F);
    hashed_addr[2] = ((row_addr >>  8) & 0x00FF)
      | ((row_addr <<  8) & 0x7F00);
    hashed_addr[3] = ((row_addr << 12) & 0x7000)
      | ((row_addr >>  4) & 0x0FFF);
  }
  else if (bf_size <= 65536){
    /*|----Selecting the bits for hash functions - 65536 counters----|
     *|RowID | 15 14 13 12 | 11 10  9  8 |  7  6  5  4 |  3  2  1  0 |
     *|Counts|  3  3  3  3 |  3  3  3  3 |  3  3  3  3 |  3  3  3  3 |
     *|------|-------------------------------------------------------|
     *|BL #1 | 15 14 13 12 | 11 10  9  8 |  7  6  5  4 |  3  2  1  0 |
     *|BL #2 |  3  2  1  0 | 15 14 13 12 | 11 10  9  8 |  7  6  5  4 |
     *|BL #3 |  7  6  5  4 |  3  2  1  0 | 15 14 13 12 | 11 10  9  8 |
     *|BL #4 | 11 10  9  8 |  7  6  5  4 |  3  2  1  0 | 15 14 13 12 |
     *|--------------------------------------------------------------|
     */
    hashed_addr[0] = row_addr;
    hashed_addr[1] = ((row_addr >> 12) & 0x000F)
      | ((row_addr <<  4) & 0xFFF0);
    hashed_addr[2] = ((row_addr >>  8) & 0x00FF)
      | ((row_addr <<  8) & 0xFF00);
    hashed_addr[3] = ((row_addr >>  4) & 0x0FFF)
      | ((row_addr << 12) & 0xF000);
  }
  else {
    cerr << "Hash functions do not support BF_SIZE " << bf_size << "." << endl;
    assert(false);
  }

  for (int i = 0; i < NUM_HASH_FUNC ; i++){
    hashed_addr[i] = hashed_addr[i] ^ seed;
    if (hashed_addr[i] >= bf_size){
      cerr << "hashed_addr["<<i<<"] = "<<hashed_addr[i]<<" >= "<<bf_size<<endl;
      assert(false);
    }
  }
}

int h3_bloom_filter_t::insert(uint16_t row_addr)
{
  apply_hash_function(row_addr);
  for (int i = 0; i < NUM_HASH_FUNC ; i++){
    cnt_arr[hashed_addr[i]] ++;
  }
  cumulative_count ++;
  return cumulative_count;
}

bool h3_bloom_filter_t::test(uint16_t row_addr)
{
  if (get_act_cnt(row_addr) >= nth){
    return true;
  }
  return false;
}

int h3_bloom_filter_t::get_act_cnt(uint16_t row_addr)
{
  apply_hash_function(row_addr);

  int min_cnt = 500000;
  for (int i = 0 ; i < 4 ; i++){
    if (cnt_arr[hashed_addr[i]] < min_cnt){
      min_cnt = cnt_arr[hashed_addr[i]];
    }
  }
  return min_cnt;
}
