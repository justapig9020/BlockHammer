#ifndef ROWHAMMER_H
#define ROWHAMMER_H

#include <string>
#include <vector>
#include <deque>
#include <queue>
#include <iterator>
#include <cmath>
#include <algorithm>
#include <time.h>
#include <limits.h>
#include <numeric>
#include <iostream>

#include "Config.h"
#include "BloomFilter.h"
#include "Statistics.h"

#define NUM_CORES 32 // Bad coding. Fix this in the future.

// Optional statistics flags
// #define COLLECT_ROWACTCNT // collects and dumps activation count per row
// #define COLLECT_ROWSTATES // collects and dumps opened and closed states of rows
// #define COLLECT_ROWBLOCKS // collects and dumps a list of blocked and nonblocked rows

using namespace std;

namespace ramulator
{

#ifdef COLLECT_ROWACTCNT
  struct row
  {
    int act_cnt;
    long first_access;
  };
#endif

  struct ActWindowEntry
  {
    int row_id;
    long timestamp;
  };

  struct mrloc
  {
    deque<long> mrloc_queue;
    int size;
  };

  struct twice_table_entry
  {
    bool valid;
    long act_cnt;
    long life;
  };

  struct cbt_counter
  {
    int counter_value;
    int upper_limit;
    int lower_limit;
    int counter_level;
  };

  struct prohit
  {
    deque<long> hot_rows;
    deque<long> cold_rows;
    int hot_entries;
    int cold_entries;
    int pr_insert_thres;
  };

  struct graphene
  {
    int k;
    long W;
    long T;
    long Nentry;
    long reset_time;
  };

  enum ROWSTATE
  {
    OPENED,
    CLOSED,
    NUM_ROWSTATES
  };

  class RowhammerDefense
  {
  protected:
    const Config &configs;

    enum ROWHAMMER_DEFENSE
    {
      NONE,        // Baseline: No RowHammer defense mechanism is implemented
      PARA,        // Y. Kim et al. ``Flipping Bits...,'' in ISCA'14
      CBT,         // S. M. Seyedzadeh et al., ``Counter-Based...,” CAL'17.
      PROHIT,      // M. Son et al., ``Making DRAM Stronger Against Row Hammering,'' in DAC'17
      MRLOC,       // J. M. You et al., ``MRLoc: Mitigating Row-Hammering Based on Memory Locality,'' in DAC'19
      TWICE,       // E. Lee et al., ``TWiCe: Preventing Row-Hammering...,'' in ISCA'19.
      GRAPHENE,    // Y. Park et al., ``Graphene: Strong yet Lightweight Row Hammer Protection,'' in MICRO'20
      BLOCKHAMMER, // A. G. Yaglikci et al., ``BlockHammer: Preventing RowHammer at Low Cost...'' in HPCA'21
      NUM_METHODS
    } method;

    string comp_name; // A unique name for each RowHammer object to identify in stats
    bool print_conf;  // Print out the configuration?
    long clk;
    long next_clk_to_dump;
    bool is_verbose = false;
    int phase_number;
    // We collect and reset statistics at the end of each phase. Currently there are only two phases:
    // 0) warmup and 1) simulation, but this can be extended (e.g., a phase per tREFW).

    // Rowhammer characteristics
    long rowhammer_threshold_trefw;
    long rowhammer_threshold_tcbf;
    int blast_radius;

    // System parameters
    double tCK;     // clock period in ns
    long nRC;       // min row activation cycle in a bank in clks
    long nREFW;     // refresh window in clks
    long nREFI;     // refresh interval in clks
    long n_act_max; // max num of ACTs in a bank that can fit in a refresh window
    long num_tcbfs; // number of tCBF time windows elapsed since the simulation started

    // Defense mechanism: PARA
    float para_threshold;
    bool para_above = true;        // refresh the row above (true) or below (false)
    unsigned int para_seed = 1337; // a static randomly generated number for deterministic simulation
    // PARA ends

    // Defense mechanism: Blockhammer
    vector<ActWindowEntry> last_activates;
    int max_reached_size_of_last_activates;
    float blockhammer_threshold;
    double blockhammer_window_size;
    int blockhammer_dryrun;
    h3_bloom_filter_t bf[2];
    long bf_start_time[2];
    long hammer_cnts[2][NUM_CORES];
    double hammer_probs[NUM_CORES];
    int active_bloom_filter;
    int blacklisted_act_budget;
    bool reset_other;
    int num_cores;
    int n_bf_window;
    int blockhammer_nth; // configs.get_int("blockhammer_nth");
    int blockhammer_nbf; // configs.get_int("blockhammer_nbf");
    int bf_size;         // configs.get_int("bf_size");
    float throttle_threshold;
    double t_delay;
    // Blockhammer ends

    // Defense mechanisms: TWiCe
    map<int, twice_table_entry> twice_table;
    float row_hammering_threshold;
    float twice_pruning_interval_threshold;
    long twice_threshold;
    // TWiCe ends

    // Defense mechanisms: CBT
    vector<cbt_counter> cbt_counters_per_bank;
    vector<int> cbt_thresholds;
    int last_activated;
    int cbt_rows_per_bank;
    int cbt_total_levels;
    int cbt_counter_no;
    long last_set_counter_population;
    long last_iterator;
    long partial_refresh_counter;
    // CBT ends

    // Defense Mechanism: Graphene
    vector<long> graphene_table_rows;
    vector<long> graphene_table_cnts;
    long graphene_spillover_cnt = 0;
    // Graphene ends

    // Refresh bookkeeping
    int ref_batch_sz;
    int refresh_pointer;
    int num_total_rows;
// Refresh ends

// Collecting stats for the ground truth
#ifdef COLLECT_ROWSTATES
    map<int, vector<long>> act_logs; // a vector of activation logs per row
    map<long, long> act_intervals;
    map<int, pair<long, ROWSTATE>> row_states;
    map<long, long> num_hot_rows;
    map<ROWSTATE, map<long, long>> state_length_distr;
    map<long, long> nth_distr;
    map<long, long> nbf_distr;
    map<int, long> hammer_cnt;
    map<int, long long> last_hammer_start;
    map<unsigned long long, map<unsigned long long, unsigned long long>> nth_nbf_distr; //<hammer_cnt, <nbf/nth, cnt>>
    long long glob_act_cnt;
#endif

#ifdef COLLECT_ROWACTCNT
    map<int, int> rhli_act_cnts;
    map<int, row> rhli_rows;
#endif
    // Ground truth statistics ends

    // Defining a struct for each defense mechanism
    struct prohit prh;
    struct mrloc mrloc;
    struct graphene graphene;
    // struct blockhammer bh;

    map<int, pair<int, int>> blocked_rows;    // row_id:<cnt, real_hammer>
    map<int, pair<int, int>> nonblocked_rows; // row_id:<cnt, real_hammer>

    string ber_distr_file,
        ber_distr_per_row_file,
        blocked_rows_file,
        nonblocked_rows_file,
        activation_interval_file,
        state_length_file,
        num_hot_rows_file,
        nth_nbf_distr_file,
        hammer_probs_file,
        rhli_per_row_file,
        rhli_hist_file;

    // VectorStat num_issued_risky_acts;
    VectorStat num_blocked_acts;
    VectorStat num_false_positives;
    VectorStat num_issued_refs;
    VectorStat num_issued_acts;
    // VectorStat rowhammer_act_cnts;
    VectorStat num_rows;
    VectorStat coreblock_truepositives;
    VectorStat coreblock_falsepositives;
    VectorStat coreblock_falsenegatives;
    VectorStat coreblock_truenegatives;

    VectorStat hammer_prob_core0;
    VectorStat hammer_prob_core1;
    VectorStat hammer_prob_core2;
    VectorStat hammer_prob_core3;
    VectorStat hammer_prob_core4;
    VectorStat hammer_prob_core5;
    VectorStat hammer_prob_core6;
    VectorStat hammer_prob_core7;

#ifdef COLLECT_ROWSTATES
    VectorStat avg_num_opened_rows;
    VectorStat avg_closed_duration;
    VectorStat min_closed_duration;
    VectorStat max_closed_duration;
    VectorStat min_closed_duration_90_percentile;
    VectorStat max_closed_duration_90_percentile;
    VectorStat avg_opened_duration;
    VectorStat min_opened_duration;
    VectorStat max_opened_duration;
    VectorStat min_opened_duration_90_percentile;
    VectorStat max_opened_duration_90_percentile;
    VectorStat min_nth, max_nth, avg_nth;
    VectorStat min_nth_90_percentile, max_nth_90_percentile;
    VectorStat min_nbf, max_nbf, avg_nbf;
    VectorStat min_nbf_90_percentile, max_nbf_90_percentile;
    VectorStat nth_common_case, nbf_common_case;
#endif

  public:
    RowhammerDefense(const Config &configs,
                     double tCK, long nREFI, int nRC,
                     string comp_name, int num_total_rows);
    ~RowhammerDefense();
    void tick(long clk);
    void finish(long clk);
    void init_stats();
    void reload_options();
    void open_hammer_probs_file();
#ifdef COLLECT_ROWACTCNT
    void dump_rhli_hist();
    void dump_rhli_per_row();
#endif
    void append_hammer_probs_file();
    void dump_blocked_rows();
#ifdef COLLECT_ROWSTATES
    void dump_activation_intervals()
#endif
        float get_throttling_coeff(int row_id, int coreid, bool is_real_hammer);
    // This function is called before issuing a row activation.
    // If the row is blacklisted and recently activated, the function returns the clock cycle until when the activation needs to be stalled
    // If the activation is ok to issue, the function returns -1, so that the current clock will be greater than it.
    long is_rowhammer_safe(int row_id, long clk, bool is_real_hammer, int coreid);
    long does_blockhammer_approve(int row_id, long clk, bool is_real_hammer);
    int get_row_to_refresh(int row_id, long clk, int adj_row_refresh_cnt, bool is_real_hammer, int coreid);
    int refresh_tick(long clk);
#ifdef COLLECT_ROWACTCNT
    void update_rhli_stats(int row_id, long clk);
#endif
    void append_act(int row_id, long clk, bool is_ref, bool is_real_hammer);
    long mrloc_update(struct mrloc *mrloc, long row, long neighbor);
    void pro_hit_update(struct prohit *prh, long row, long neighbor);
  };
}

/*
  [1] Kim et al. "Flipping Bits in Memory Without Accessing Them:
      An Experimental Study of DRAM Disturbance Errors," ISCA 2014
*/

#endif
