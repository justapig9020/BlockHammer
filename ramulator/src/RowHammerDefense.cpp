// #define DEBUG
#include "debug.h"

#include "RowHammerDefense.h"

#define NUM_CORES 32 // Bad coding. Fix this in the future.

// Optional statistics flags
// #define COLLECT_ROWACTCNT // collects and dumps activation count per row
// #define COLLECT_ROWSTATES // collects and dumps opened and closed states of rows
// #define COLLECT_ROWBLOCKS // collects and dumps a list of blocked and nonblocked rows

namespace ramulator
{
    RowhammerDefense::RowhammerDefense(const Config &configs,
                                       double tCK, long nREFI, int nRC,
                                       string comp_name, int num_total_rows) : configs(configs)
    {
        this->phase_number = 0;
        this->comp_name = comp_name;

        this->print_conf = (comp_name == "0_0_0_0");

        this->tCK = tCK;
        this->nREFI = nREFI;
        this->nREFW = (long)nREFI * 8192; // assumes 8K REF commands are issued in a tREFW
        this->next_clk_to_dump = this->nREFW;
        this->nRC = nRC;
        this->n_act_max = this->nREFW / this->nRC;
        this->rowhammer_threshold_trefw = configs.get_long("rowhammer_threshold");
        this->blast_radius = configs.get_long("rowhammer_br");
        this->num_tcbfs = 0;
        if (this->print_conf)
        {
            std::cout << "Initializing RowHammer Parameters:" << std::endl;
            std::cout << "  tCK  :" << this->tCK << std::endl;
            std::cout << "  nREFW:" << this->nREFW << std::endl;
            std::cout << "  nREFI:" << this->nREFI << std::endl;
            std::cout << "  nRC  :" << this->nRC << std::endl;
            std::cout << "  nRH  :" << this->rowhammer_threshold_trefw << std::endl;
        }

        // Initializing Refresh Parameters
        this->ref_batch_sz = num_total_rows / 8205; // 8205 is the number of REF commands in a 64ms refresh window.
        this->num_total_rows = num_total_rows;
        this->refresh_pointer = 0;

        // Core-wise throttling in the memory controller queue.
        num_cores = configs.get_int("cores");
        assert(num_cores <= NUM_CORES); // @Giray: Bad coding, fix this in the future.
        for (int i = 0; i < num_cores; i++)
        {
            hammer_cnts[0][i] = 0;
            hammer_cnts[1][i] = 0;
            hammer_probs[i] = 0;
        }
        open_hammer_probs_file();
        if (this->print_conf)
        {
            std::cout << "  Number of cores: " << num_cores << std::endl;
        }

        num_blocked_acts
            .init(2)
            .name("num_blocked_acts_" + this->comp_name)
            .desc("Number of blocked ACTs by blockhammer")
            .precision(0);

        num_issued_refs
            .init(2)
            .name("num_issued_prev_refs_" + this->comp_name)
            .desc("Number of issued preventive refreshes by a rowhammer protection mechanism")
            .precision(0);

        num_issued_acts
            .init(2)
            .name("num_issued_acts_" + this->comp_name)
            .desc("Total number of issued activations")
            .precision(0);

        num_rows
            .init(2)
            .name("num_rows_" + this->comp_name)
            .desc("Memory footprint of the program in terms of number of DRAM rows, touched at least once.")
            .precision(0);

        coreblock_truepositives
            .init(2)
            .name("coreblock_truepositives_" + this->comp_name)
            .desc("Number of times that a RowHammer core was throttled.")
            .precision(0);

        coreblock_falsepositives
            .init(2)
            .name("coreblock_falsepositives_" + this->comp_name)
            .desc("Number of times that a benign core was throttled.")
            .precision(0);

        coreblock_falsenegatives
            .init(2)
            .name("coreblock_falsenegatives_" + this->comp_name)
            .desc("Number of times that a RowHammer core was not throttled.")
            .precision(0);

        coreblock_truenegatives
            .init(2)
            .name("coreblock_truenegatives_" + this->comp_name)
            .desc("Number of times that a benign core was not throttled.")
            .precision(0);

        hammer_prob_core0
            .init(2)
            .name("hammer_prob_core0_" + this->comp_name)
            .desc("Probability of core 0 being a RowHammer attack.")
            .precision(4);
        hammer_prob_core1
            .init(2)
            .name("hammer_prob_core1_" + this->comp_name)
            .desc("Probability of core 1 being a RowHammer attack.")
            .precision(4);
        hammer_prob_core2
            .init(2)
            .name("hammer_prob_core2_" + this->comp_name)
            .desc("Probability of core 2 being a RowHammer attack.")
            .precision(4);
        hammer_prob_core3
            .init(2)
            .name("hammer_prob_core3_" + this->comp_name)
            .desc("Probability of core 3 being a RowHammer attack.")
            .precision(4);
        hammer_prob_core4
            .init(2)
            .name("hammer_prob_core4_" + this->comp_name)
            .desc("Probability of core 4 being a RowHammer attack.")
            .precision(4);
        hammer_prob_core5
            .init(2)
            .name("hammer_prob_core5_" + this->comp_name)
            .desc("Probability of core 5 being a RowHammer attack.")
            .precision(4);
        hammer_prob_core6
            .init(2)
            .name("hammer_prob_core6_" + this->comp_name)
            .desc("Probability of core 6 being a RowHammer attack.")
            .precision(4);
        hammer_prob_core7
            .init(2)
            .name("hammer_prob_core7_" + this->comp_name)
            .desc("Probability of core 7 being a RowHammer attack.")
            .precision(4);
#ifdef COLLECT_ROWSTATES

        avg_num_hammered_rows
            .init(2)
            .name("avg_num_hammered_rows_" + this->comp_name)
            .desc("Avg. number of hammered rows at a given time throughout the application.")
            .precision(4);

        avg_release_duration
            .init(2)
            .name("avg_len_of_rel_state_" + this->comp_name)
            .desc("avg. len of rel state")
            .precision(4);
        min_release_duration
            .init(2)
            .name("min_len_of_rel_state_" + this->comp_name)
            .desc("min. len of rel state")
            .precision(0);
        max_release_duration
            .init(2)
            .name("max_len_of_rel_state_" + this->comp_name)
            .desc("max. len of rel state")
            .precision(0);
        min_release_duration_90_percentile
            .init(2)
            .name("min90_len_of_rel_state_" + this->comp_name)
            .desc("min. len of rel state (with 90%ile coverage)")
            .precision(0);
        max_release_duration_90_percentile
            .init(2)
            .name("max90_len_of_rel_state_" + this->comp_name)
            .desc("max. len of rel state (with 90%ile coverage)")
            .precision(0);

        avg_hammer_duration
            .init(2)
            .name("avg_len_of_hammer_state_" + this->comp_name)
            .desc("avg. len of hammer state ")
            .precision(4);
        min_hammer_duration
            .init(2)
            .name("min_len_of_hammer_state_" + this->comp_name)
            .desc("min. len of hammer state ")
            .precision(0);
        max_hammer_duration
            .init(2)
            .name("max_len_of_hammer_state_" + this->comp_name)
            .desc("max. len of hammer state ")
            .precision(0);
        min_hammer_duration_90_percentile
            .init(2)
            .name("min90_len_of_hammer_state_" + this->comp_name)
            .desc("min. len of hammer state  (with 90%ile coverage)")
            .precision(0);
        max_hammer_duration_90_percentile
            .init(2)
            .name("max90_len_of_hammer_state_" + this->comp_name)
            .desc("max. len of hammer state  (with 90%ile coverage)")
            .precision(0);

        min_nth
            .init(2)
            .name("min_nth_" + this->comp_name)
            .desc("min. Nth")
            .precision(0);
        max_nth
            .init(2)
            .name("max_nth_" + this->comp_name)
            .desc("max. Nth")
            .precision(0);
        avg_nth
            .init(2)
            .name("avg_nth_" + this->comp_name)
            .desc("avg Nth")
            .precision(4);
        min_nth_90_percentile
            .init(2)
            .name("min90_nth_" + this->comp_name)
            .desc("min. Nth  (with 90%ile coverage)")
            .precision(0);
        max_nth_90_percentile
            .init(2)
            .name("max90_nth_" + this->comp_name)
            .desc("max. Nth  (with 90%ile coverage)")
            .precision(0);

        min_nbf
            .init(2)
            .name("min_nbf_" + this->comp_name)
            .desc("min. Nbf")
            .precision(0);
        max_nbf
            .init(2)
            .name("max_nbf_" + this->comp_name)
            .desc("max. Nbf")
            .precision(0);
        avg_nbf
            .init(2)
            .name("avg_nbf_" + this->comp_name)
            .desc("avg Nbf")
            .precision(4);
        min_nbf_90_percentile
            .init(2)
            .name("min90_nbf_" + this->comp_name)
            .desc("min. Nbf  (with 90%ile coverage)")
            .precision(0);
        max_nbf_90_percentile
            .init(2)
            .name("max90_nbf_" + this->comp_name)
            .desc("max. Nbf  (with 90%ile coverage)")
            .precision(0);

        nth_common_case
            .init(2)
            .name("nth_common_case" + this->comp_name)
            .desc("Observed Nth in the worst case, where Nth is max and Nbf is min.")
            .precision(2);

        nbf_common_case
            .init(2)
            .name("nbf_common_case" + this->comp_name)
            .desc("Observed Nbf in the worst case, where Nth is max and Nbf is min.")
            .precision(2);
#endif

        // MAC: Maximum rowhammer-safe activation count
        // this->maximum_activation_count = (long) (nREFI / this->min_safe_activation_interval);
        //
        // std::cout << "Activating one row more than "
        //      << this->maximum_activation_count
        //      << " times will be considered as it introduces rowhammer effect."
        //      << std::endl;

        this->init_stats();
    }

    RowhammerDefense::~RowhammerDefense()
    {
        // final();
    }

    void RowhammerDefense::tick(long clk)
    {
        this->clk = clk;
        if (this->method != ROWHAMMER_DEFENSE::BLOCKHAMMER)
          return;
        if (clk - bf_start_time[active_bloom_filter] > this->nREFW / this->n_bf_window)
        { // switch filters
            debug("switching bloom filter in tick");
            append_hammer_probs_file();
            bf[active_bloom_filter].clear();
            bf_start_time[active_bloom_filter] = clk;
            for (int i = 0; i < num_cores; i++)
            {
                hammer_cnts[active_bloom_filter][i] = 0;
            }
            active_bloom_filter = 1 - active_bloom_filter;
            debug("bloom filter refreshed");
        }
    }

    void RowhammerDefense::finish(long clk)
    {
#ifdef COLLECT_ROWSTATES
        this->dump_activation_intervals();
        this->dump_state_length();
#endif
#ifdef COLLECT_ROWACTCNT
        this->dump_rhli_per_row();
        this->dump_rhli_hist();
#endif
        // Cleaning up the last activates
        this->last_activates.erase(
            this->last_activates.begin(), this->last_activates.end());
        this->blocked_rows.erase(this->blocked_rows.begin(), this->blocked_rows.end());
        this->nonblocked_rows.erase(this->nonblocked_rows.begin(), this->nonblocked_rows.end());
#ifdef COLLECT_ROWSTATES
        this->act_intervals.erase(this->act_intervals.begin(), this->act_intervals.end());
        this->state_length_distr.erase(this->state_length_distr.begin(), this->state_length_distr.end());
        this->nth_distr.erase(this->nth_distr.begin(), this->nth_distr.end());
        this->nbf_distr.erase(this->nbf_distr.begin(), this->nbf_distr.end());
        this->hammer_cnt.erase(this->hammer_cnt.begin(), this->hammer_cnt.end());
        this->last_hammer_start.erase(this->last_hammer_start.begin(), this->last_hammer_start.end());
        this->nth_nbf_distr.erase(this->nth_nbf_distr.begin(), this->nth_nbf_distr.end());

#endif

        this->hammer_prob_core0[this->phase_number] = hammer_probs[0];
        this->hammer_prob_core1[this->phase_number] = hammer_probs[1];
        this->hammer_prob_core2[this->phase_number] = hammer_probs[2];
        this->hammer_prob_core3[this->phase_number] = hammer_probs[3];
        this->hammer_prob_core4[this->phase_number] = hammer_probs[4];
        this->hammer_prob_core5[this->phase_number] = hammer_probs[5];
        this->hammer_prob_core6[this->phase_number] = hammer_probs[6];
        this->hammer_prob_core7[this->phase_number] = hammer_probs[7];
    }

    void RowhammerDefense::init_stats()
    {
// Reset stats
#ifdef COLLECT_ROWSTATES
        this->glob_act_cnt = 0;
#endif
        // Choose which protection mechanism to use.
        string method_str = configs.get_str("rowhammer_defense");
        // Initializing BlockHammer parameters

        this->blockhammer_dryrun = configs.get_int("blockhammer_dryrun");
        this->blockhammer_nth = configs.get_int("blockhammer_nth");
        this->blockhammer_nbf = configs.get_int("blockhammer_nbf");
        this->bf_size = configs.get_int("bf_size");
        this->n_bf_window = this->n_act_max / this->blockhammer_nbf;                          // Num of tCBF windows in a tREFW window
        this->rowhammer_threshold_tcbf = this->rowhammer_threshold_trefw / this->n_bf_window; // n_rh_bf
        this->throttle_threshold = configs.get_float("blockhammer_tth");

        this->method = ROWHAMMER_DEFENSE::NONE;

        if (method_str == "para")
        {
            this->method = ROWHAMMER_DEFENSE::PARA;
            this->para_seed = 1337;
            this->para_threshold = configs.get_float("para_threshold");
            std::cout << "PARA fights against rowhammer with the probability threshold of ";
            std::cout << this->para_threshold << " at " << this->comp_name << std::endl;
        }

        else if (method_str == "blockhammer")
        {
            this->method = ROWHAMMER_DEFENSE::BLOCKHAMMER;
            // BlockHammer does not delay activations before a row's activation count exceeds NTH
            // Therefore, in an NCBF activation window, NCBF - NTH activations are blacklisted.
            blacklisted_act_budget = this->rowhammer_threshold_tcbf - this->blockhammer_nth;

            // Calculating tDelay
            // The maximum activation rate of a DRAM row should be tREFW / NRH
            double t_actmax = (double)this->nREFW / this->rowhammer_threshold_trefw;
            // The overall activation rate of a DRAM row can be as large as t_actmax
            // The first NTH row activations are not delayed. So, they take t1 = NTH * tRC
            // Remaining (NCBF - NTH) row activations are delayed by tDelay. So they take t2 = (NCBF-NTH) * tDelay
            // Now in total performing NCBF row activations should take at least t1 + t2 = NCBF * (tREFW/NRH) time
            // (NTH * tRC) + ((NCBF-NTH) * tDelay) = NCBF * (tREFW/NRH)
            // Solving this equation for tDelay:
            // tDelay = (NCBF * t_actmax - NTH * tRC) / (NCBF - NTH)
            this->t_delay = (rowhammer_threshold_tcbf * t_actmax - this->blockhammer_nth * this->nRC) / blacklisted_act_budget;
            std::cout << "BlockHammer activated with a blacklisting threshold of " << this->blockhammer_nth << " at " << this->comp_name << std::endl;
            if (this->print_conf)
            {
                std::cout << "  BlockHammer NTH : " << dec << this->blockhammer_nth << std::endl
                          << "  BlockHammer NBF : " << dec << this->blockhammer_nbf << std::endl
                          << "  tREFW / tRC     : " << dec << this->n_act_max << std::endl
                          << "  N_BFWindow      : " << dec << n_bf_window << std::endl
                          << "  NRH in a tCBF   : " << dec << rowhammer_threshold_tcbf << std::endl
                          << "  tDelay          : " << dec << this->t_delay << std::endl
                          << "  Blacklisted ACTs: " << dec << blacklisted_act_budget << std::endl
                          << std::endl;
            }

            this->active_bloom_filter = 0;
            bf[0].initialize(bf_size, this->blockhammer_nth, this->blockhammer_nbf, 31243); // 31243 is a randomly generated seed
            bf[1].initialize(bf_size, this->blockhammer_nth, this->blockhammer_nbf, 54322); // 54322 is a randomly generated seed
            bf_start_time[0] = 0;
            bf_start_time[1] = 0;

            if (this->print_conf)
            {
                std::cout << "  Bloom filter triggers blockhammer after "
                          << dec << this->blockhammer_nth << " acts." << std::endl
                          << "  Then BlockHammer enforces a delay of "
                          << dec << t_delay
                          << " clks between two consecutive acts targeting the same row."
                          << std::endl;
            }
        }

        else if (method_str == "twice")
        {
            this->method = ROWHAMMER_DEFENSE::TWICE;
            this->twice_threshold = configs.get_int("twice_threshold");
            std::cout << "TWiCe activated with threshold: " << this->twice_threshold << " at " << this->comp_name << std::endl;
        }

        else if (method_str == "cbt")
        {
            this->method = ROWHAMMER_DEFENSE::CBT;
            std::cout << "CBT activated at " << this->comp_name << std::endl;

            last_set_counter_population = -1;
            last_iterator = 0;
            partial_refresh_counter = 0;
            last_activated = 0;

            cbt_rows_per_bank = 65536;
            cbt_total_levels = configs.get_long("cbt_total_levels");
            cbt_counter_no = configs.get_long("cbt_counter_no");
            cbt_counter counter;
            counter.counter_value = 0;
            counter.counter_level = 0;
            counter.upper_limit = cbt_rows_per_bank - 1;
            counter.lower_limit = 0;
            for (int i = 0; i < cbt_total_levels; ++i)
            {
                cbt_thresholds.push_back(rowhammer_threshold_trefw / (pow(2, (cbt_total_levels - 1 - i))));
            }
            for (int i = 0; i < cbt_counter_no; ++i)
            {
                cbt_counters_per_bank.push_back(counter);
                counter.upper_limit = 0;
            }
        }

        else if (method_str == "prohit")
        {
            this->method = ROWHAMMER_DEFENSE::PROHIT;
            prh.hot_entries = configs.get_int("prh_hot");
            prh.cold_entries = configs.get_int("prh_cold");
            std::cout << "PRoHIT activated with: " << configs.get_int("prh_hot")
                      << "hot rows and " << configs.get_int("prh_cold") << " cold rows at " << this->comp_name << std::endl;
        }

        else if (method_str == "mrloc")
        {
            this->method = ROWHAMMER_DEFENSE::MRLOC;
            mrloc.size = 15; // Hard-coded based on the implementation in the original paper.
        }

        else if (method_str == "graphene")
        {
            this->method = ROWHAMMER_DEFENSE::GRAPHENE;
            graphene.T = configs.get_int("grt");
            graphene.k = configs.get_int("grk");
            graphene.W = configs.get_int("grw"); // this->n_act_max / graphene.k;
            if (graphene.T == 0)
                graphene.T = this->rowhammer_threshold_trefw / (2 * (graphene.k + 1));
            graphene.Nentry = floor(graphene.W * 1.0 / graphene.T - 1) + 1;
            graphene.reset_time = this->nREFW / graphene.k;
            graphene_table_rows.resize(graphene.Nentry, -1);
            graphene_table_cnts.resize(graphene.Nentry, 0);
            graphene_spillover_cnt = 0;

            std::cout << "Graphene is activated with " << graphene.Nentry << " table entries and " << graphene.T << " threshold at " << this->comp_name << std::endl;
            std::cout << "Graphene will be reset every " << graphene.reset_time << "clks (" << graphene.k << " time in a REFW)." << std::endl;
        }

        else
            std::cout << "Proceeding with no RowHammer defense at " << this->comp_name << std::endl;

#ifdef COLLECT_BER
        ber_distr_file = configs.get_str("outdir") + "/" + configs.get_str("rowhammer_stats") + "_" + this->comp_name + "_phase" + to_string(this->phase_number) + "_ber_distr.csv";
        ber_distr_per_row_file = configs.get_str("outdir") + "/" + configs.get_str("rowhammer_stats") + "_" + this->comp_name + "_phase" + to_string(this->phase_number) + "_ber_distr_per_row.csv";
#endif
#ifdef COLLECT_ROWACTCNT
        rhli_per_row_file = configs.get_str("outdir") + "/" + configs.get_str("rowhammer_stats") + "_" + this->comp_name + "_phase" + to_string(this->phase_number) + "_rhli_per_row.csv";
        rhli_hist_file = configs.get_str("outdir") + "/" + configs.get_str("rowhammer_stats") + "_" + this->comp_name + "_phase" + to_string(this->phase_number) + "_rhli_hist.csv";
#endif
        blocked_rows_file = configs.get_str("outdir") + "/" + configs.get_str("rowhammer_stats") + "_" + this->comp_name + "_phase" + to_string(this->phase_number) + "_blocked_rows.csv";
        nonblocked_rows_file = configs.get_str("outdir") + "/" + configs.get_str("rowhammer_stats") + "_" + this->comp_name + "_phase" + to_string(this->phase_number) + "_nonblocked_rows.csv";
        hammer_probs_file = configs.get_str("outdir") + "/" + configs.get_str("rowhammer_stats") + "_" + this->comp_name + "_phase" + to_string(this->phase_number) + "_hammer_probs.csv";
#ifdef COLLECT_ROWSTATES
        activation_interval_file = configs.get_str("outdir") + "/" + configs.get_str("rowhammer_stats") + "_" + this->comp_name + "_phase" + to_string(this->phase_number) + "_activation_intervals.csv";
        state_length_file = configs.get_str("outdir") + "/" + configs.get_str("rowhammer_stats") + "_" + this->comp_name + "_phase" + to_string(this->phase_number) + "_hot_cold_state_lengths.csv";
        num_hot_rows_file = configs.get_str("outdir") + "/" + configs.get_str("rowhammer_stats") + "_" + this->comp_name + "_phase" + to_string(this->phase_number) + "_num_hammered_rows.csv";
        nth_nbf_distr_file = configs.get_str("outdir") + "/" + configs.get_str("rowhammer_stats") + "_" + this->comp_name + "_phase" + to_string(this->phase_number) + "_nth_distr.csv";
#endif
        this->num_blocked_acts[this->phase_number] = 0;

        this->num_rows[this->phase_number] = 0;
        this->coreblock_truepositives[this->phase_number] = 0;
        this->coreblock_falsepositives[this->phase_number] = 0;
        this->coreblock_falsenegatives[this->phase_number] = 0;
        this->coreblock_truenegatives[this->phase_number] = 0;
        this->hammer_prob_core0[this->phase_number] = 0;
        this->hammer_prob_core1[this->phase_number] = 0;
        this->hammer_prob_core2[this->phase_number] = 0;
        this->hammer_prob_core3[this->phase_number] = 0;
        this->hammer_prob_core4[this->phase_number] = 0;
        this->hammer_prob_core5[this->phase_number] = 0;
        this->hammer_prob_core6[this->phase_number] = 0;
        this->hammer_prob_core7[this->phase_number] = 0;

#ifdef COLLECT_ROWSTATES

        this->avg_num_hammered_rows[this->phase_number] = 0;

        this->avg_release_duration[this->phase_number] = 0;
        this->min_release_duration[this->phase_number] = 0;
        this->max_release_duration[this->phase_number] = 0;
        this->min_release_duration_90_percentile[this->phase_number] = 0;
        this->max_release_duration_90_percentile[this->phase_number] = 0;

        this->avg_hammer_duration[this->phase_number] = 0;
        this->min_hammer_duration[this->phase_number] = 0;
        this->max_hammer_duration[this->phase_number] = 0;
        this->min_hammer_duration_90_percentile[this->phase_number] = 0;
        this->max_hammer_duration_90_percentile[this->phase_number] = 0;

        this->min_nth[this->phase_number] = 0;
        this->max_nth[this->phase_number] = 0;
        this->avg_nth[this->phase_number] = 0;
        this->min_nth_90_percentile[this->phase_number] = 0;
        this->max_nth_90_percentile[this->phase_number] = 0;

        this->min_nbf[this->phase_number] = 0;
        this->max_nbf[this->phase_number] = 0;
        this->avg_nbf[this->phase_number] = 0;
        this->min_nbf_90_percentile[this->phase_number] = 0;
        this->max_nbf_90_percentile[this->phase_number] = 0;

        this->nth_common_case[this->phase_number] = 0;
        this->nbf_common_case[this->phase_number] = 0;
#endif
    }

    void RowhammerDefense::reload_options()
    {
        // Dump Warmup of current phase, reset stats and increment phase number.
        finish(0);
        this->phase_number++;
        init_stats();
    }

    void RowhammerDefense::open_hammer_probs_file()
    {
        ofstream outfile;
        outfile.open(hammer_probs_file, ios::out | ios::trunc);
        outfile << "clk,core0,core1,core2,core3,core4,core5,core6,core7" << std::endl;
        outfile.close();
    }

#ifdef COLLECT_ROWACTCNT
    void dump_rhli_hist()
    {
        ofstream outfile;
        outfile.open(rhli_hist_file, ios::out | ios::trunc);
        outfile << "act_cnt,num_rows" << std::endl;
        for (const auto &entry : this->rhli_act_cnts)
        {
            outfile << entry.first << "," << entry.second << std::endl;
        }
        outfile.close();
    }

    void dump_rhli_per_row()
    {
        ofstream outfile;
        outfile.open(rhli_per_row_file, ios::out | ios::trunc);
        outfile << "row_id,act_cnt,first_access" << std::endl;
        for (const auto &entry : this->rhli_rows)
        {
            outfile << entry.first << "," << entry.second.act_cnt << "," << entry.second.first_access << std::endl;
        }
        outfile.close();
    }
#endif

    void RowhammerDefense::append_hammer_probs_file()
    {
        ofstream outfile;
        outfile.open(hammer_probs_file, ios::out | ios::app);
        outfile << clk;
        for (int i = 0; i < num_cores; i++)
        {
            float hammer_prob = (hammer_cnts[active_bloom_filter][i] * 1.0 / (rowhammer_threshold_tcbf - blockhammer_nth));
            hammer_probs[i] = (hammer_prob + hammer_probs[i] * num_tcbfs) / (num_tcbfs + 1);
            hammer_cnts[active_bloom_filter][i] = 0;
            outfile << "," << hammer_prob;
        }
        num_tcbfs++;
        outfile << std::endl;
    }

    void RowhammerDefense::dump_blocked_rows()
    {
        ofstream outfile;
        outfile.open(blocked_rows_file, ios::out | ios::trunc);
        outfile << "row_id,cnt,true_positive" << std::endl;
        for (const auto &entry : this->blocked_rows)
        {
            outfile << entry.first << "," << entry.second.first << "," << entry.second.second << std::endl;
        }
        outfile.close();

        ofstream outfile2;
        outfile2.open(nonblocked_rows_file, ios::out | ios::trunc);
        outfile2 << "row_id,cnt,false_negative" << std::endl;
        for (const auto &entry : this->nonblocked_rows)
        {
            outfile2 << entry.first << "," << entry.second.first << "," << entry.second.second << std::endl;
        }
        outfile2.close();
    }

#ifdef COLLECT_ROWSTATES
    void dump_activation_intervals()
    {
        ofstream outfile;
        outfile.open(activation_interval_file, ios::out | ios::trunc);
        outfile << "act_interval,cnt" << std::endl;
        for (const auto &entry : this->act_intervals)
        {
            outfile << entry.first << "," << entry.second << std::endl;
        }
        outfile.close();
    }
    void dump_state_length()
    {
        // First close the states
        for (auto &entry : this->row_states)
        {
            long duration = (this->act_logs[entry.first].back() - entry.second.first); // / this->nRC;
            // printf("Closing %d state of row %d.\n", (int) entry.second.second, entry.first);
            if (duration > 0)
            {
                if (this->state_length_distr[entry.second.second].find(duration) == this->state_length_distr[entry.second.second].end())
                {
                    this->state_length_distr[entry.second.second][duration] = 1;
                }
                else
                {
                    this->state_length_distr[entry.second.second][duration] += 1;
                }

                // update nth histogram
                if (entry.second.second == ROWSTATE::OPENED)
                {
                    if (this->nth_distr.find(this->hammer_cnt[entry.first]) == this->nth_distr.end())
                    {
                        this->nth_distr[this->hammer_cnt[entry.first]] = 1;
                    }
                    else
                    {
                        this->nth_distr[this->hammer_cnt[entry.first]] += 1;
                    }
                    this->hammer_cnt[entry.first] = 0;
                }

                if (entry.second.second == ROWSTATE::CLOSED)
                {
                    if (this->last_hammer_start.find(entry.first) != this->last_hammer_start.end())
                    {
                        long long h2h_act_cnt = this->glob_act_cnt - this->last_hammer_start[entry.first];
                        if (this->nbf_distr.find(h2h_act_cnt) == this->nbf_distr.end())
                        {
                            this->nbf_distr[h2h_act_cnt] = 1;
                        }
                        else
                        {
                            this->nbf_distr[h2h_act_cnt] += 1;
                        }
                        long hcnt = this->hammer_cnt[entry.first];
                        long hratio = (long)round(h2h_act_cnt * 1.0 / hcnt);
                        if (this->nth_nbf_distr.find(hcnt) == this->nth_nbf_distr.end() || this->nth_nbf_distr[hcnt].find(hratio) == this->nth_nbf_distr[hcnt].end())
                        {
                            this->nth_nbf_distr[hcnt][hratio] = 1;
                        }
                        else
                        {
                            this->nth_nbf_distr[hcnt][hratio] += 1;
                        }
                    }
                }

                // collect stats of number of hot rows at a given time
                {
                    int cnt = 0;
                    for (auto &entry : this->row_states)
                    {
                        num_rows[this->phase_number]++;
                        if (entry.second.second == ROWSTATE::OPENED)
                        {
                            if (clk - this->act_logs[entry.first].back() <= this->min_safe_activation_interval)
                            {
                                cnt++;
                            }
                        }
                    }
                    if (this->num_hot_rows.find(cnt) == this->num_hot_rows.end())
                    {
                        this->num_hot_rows[cnt] = 1;
                    }
                    else
                    {
                        this->num_hot_rows[cnt] += 1;
                    }
                }
            }
        }
        // std::cout << "This workload touches " << dec << num_rows[this->phase_number].value()
        //      << " rows in this phase in bank " << this->comp_name << std::endl;
        ofstream outfile1, outfile2, outfile3, outfile4;
        outfile1.open(state_length_file, ios::out | ios::trunc);
        outfile2.open(num_hot_rows_file, ios::out | ios::trunc);
        outfile3.open(nth_nbf_distr_file, ios::out | ios::trunc);

        outfile1 << "state,state_length,cnt" << std::endl;
        outfile2 << "num_hot_rows,cnt" << std::endl;
        outfile3 << "nth,nbf,cnt" << std::endl;

        for (const auto &entry : this->state_length_distr)
        {
            string state_str = (entry.first == ROWSTATE::CLOSED) ? "CLOSED" : "OPENED";
            double avg_duration = 0;
            long max_duration = 0, min_duration = this->clk;
            long max_duration_90_percentile = 0, min_duration_90_percentile = this->clk;
            long num_duration_records = 0;
            for (const auto &e : entry.second)
            {
                avg_duration =
                    avg_duration * (num_duration_records * 1.0 / (num_duration_records + e.second)) + (e.first * e.second * 1.0 / (num_duration_records + e.second));
                num_duration_records += e.second;
                if (max_duration < e.first)
                    max_duration = e.first;
                if (min_duration > e.first)
                    min_duration = e.first;
                outfile1 << state_str << "," << e.first << "," << e.second << std::endl;
            }
            long duration_record_cnt = 0;
            bool captured_10_percentile = false, captured_90_percentile = false;
            for (const auto &e : entry.second)
            {
                duration_record_cnt += e.second;
                if (!captured_10_percentile)
                    captured_10_percentile = (duration_record_cnt > num_duration_records * 0.1);
                if (captured_10_percentile)
                {
                    if (min_duration_90_percentile > e.first)
                        min_duration_90_percentile = e.first;
                }
                if (!captured_90_percentile)
                {
                    captured_90_percentile = (duration_record_cnt > num_duration_records * 0.9);
                    if (max_duration_90_percentile < e.first)
                        max_duration_90_percentile = e.first;
                }
            }

            if (entry.first == ROWSTATE::CLOSED)
            {
                avg_release_duration[this->phase_number] = avg_duration;
                min_release_duration[this->phase_number] = min_duration;
                max_release_duration[this->phase_number] = max_duration;
                min_release_duration_90_percentile[this->phase_number] = min_duration_90_percentile;
                max_release_duration_90_percentile[this->phase_number] = max_duration_90_percentile;
            }
            else
            {
                avg_hammer_duration[this->phase_number] = avg_duration;
                min_hammer_duration[this->phase_number] = min_duration;
                max_hammer_duration[this->phase_number] = max_duration;
                min_hammer_duration_90_percentile[this->phase_number] = min_duration_90_percentile;
                max_hammer_duration_90_percentile[this->phase_number] = max_duration_90_percentile;
            }
        }
        long long num_hot_row_cnt_entries = 0;
        avg_num_hammered_rows[this->phase_number] = 0;
        for (const auto &e : this->num_hot_rows)
        {
            if (e.first > 0)
            {
                avg_num_hammered_rows[this->phase_number] =
                    (avg_num_hammered_rows[this->phase_number].value() * (num_hot_row_cnt_entries * 1.0 / (num_hot_row_cnt_entries + e.second))) + (e.first * e.second * 1.0 / (num_hot_row_cnt_entries + e.second));
                num_hot_row_cnt_entries += e.second;
            }
            outfile2 << e.first << "," << e.second << std::endl;
        }
        // std::cout << "This workload hammers " << dec << avg_num_hammered_rows[this->phase_number].value()
        //      << " rows at a time in average in bank " << this->comp_name << std::endl;

        { // dump nth distr into a file and count the total of cnts.
            long long total_cnt = 0;
            // long long weighted_avg = 0;
            // bool first = true;
            map<unsigned long long, map<unsigned long long, deque<unsigned long long>>> sorted_nth_nbf;

            // std::cout << "+++++++++" << comp_name << ":" << phase_number << "+++++++++" << std::endl;
            for (auto &e : this->nth_nbf_distr)
            {
                for (auto &ee : e.second)
                {
                    long long nth = e.first, nbf = e.first * ee.first, cnt = ee.second;
                    outfile3 << dec << nth << "," << dec << nbf << "," << dec << cnt << std::endl;
                    sorted_nth_nbf[cnt][nth].push_back(nbf);
                    // std::cout << "cnt: " << dec << cnt << " nth: " << dec << nth << " nbf: " << dec << nbf << std::endl;
                    total_cnt += cnt;
                }
            }
            // std::cout << "+++++++++" << "+++++++++" << "+++++++++" << std::endl;

            // std::cout << "=========" << comp_name << ":" << phase_number << "=========" << std::endl;
            for (auto &e1 : sorted_nth_nbf)
            {
                for (auto &e2 : e1.second)
                {
                    sort(e2.second.begin(), e2.second.end());
                    // for(auto& e3 : e2.second)
                    //   std::cout << dec << e1.first << " " << dec << e2.first << " " << dec << e3 << std::endl;
                }
            }
            // std::cout << "=========" << "=========" << "=========" << std::endl;

            // clear tail
            int cnt = 0;
            int desired_coverage = (int)total_cnt >> 1;
            int c2 = 0;
            int map_size = sorted_nth_nbf.size();
            bool clean_tail = (map_size > 0);
            if (clean_tail)
            {
                c2 = sorted_nth_nbf.begin()->second.size();
                clean_tail = c2 > 0;
            }

            while (clean_tail)
            {
                // std::cout << "=========" << comp_name << ":" << phase_number << "=========" << std::endl;
                // for (auto& e1 : sorted_nth_nbf){
                //   for(auto& e2 : e1.second){
                // for(auto& e3 : e2.second)
                //   std::cout << dec << e1.first << " " << dec << e2.first << " " << dec << e3 << std::endl;
                //   }
                // }
                // std::cout << "=========" << "=========" << "=========" << std::endl;
                int c1 = sorted_nth_nbf.begin()->first;
                auto &nth_nbfs = sorted_nth_nbf.begin()->second;
                auto &nbfs = nth_nbfs.begin()->second;
                // std::cout << "Looking at nbfs: ";
                // for(auto& e : nbfs){
                //   std::cout << dec << e << " ";
                // }
                // std::cout << std::endl;
                c2 = nbfs.size();
                if (c2 > 0)
                {
                    int clear_cnt = min((desired_coverage - cnt) / c1, c2);
                    // std::cout << "I can get rid of " << dec << (desired_coverage - cnt) / c1 << " records. ";
                    // std::cout << "I have " << dec << c2 << " records. ";
                    // std::cout << "I will remove " << dec << clear_cnt << "entries" << std::endl;
                    // fflush(stdout);
                    // printf("Updating cnt..."); fflush(stdout);
                    cnt += (c1 * clear_cnt);
                    // printf(" cnt=%lld.\n", cnt); fflush(stdout);

                    bool direction = true;
                    for (int cc = 0; cc < clear_cnt; cc++)
                    {
                        if (direction)
                        {
                            // auto e = nbfs.front();
                            nbfs.pop_front();
                            // printf("erasing nbf=%llu.\n", e);
                            // fflush(stdout);
                        }
                        else
                        {
                            // auto e = nbfs.back();
                            nbfs.pop_back();
                            // printf("erasing nbf=%llu.\n", e);
                            // fflush(stdout);
                        }
                        direction = !direction;
                    }

                    if (nbfs.size() == 0)
                    {
                        // printf("Clearing the map entry that contains emptied NBF deque.\n");
                        // fflush(stdout);
                        sorted_nth_nbf.begin()->second.erase(
                            sorted_nth_nbf.begin()->second.begin());
                        if (nth_nbfs.size() == 0)
                        {
                            // printf("Erasing the map entry of NTH value that does not have any NBFs.\n");
                            // fflush(stdout);
                            sorted_nth_nbf.erase(sorted_nth_nbf.begin());
                        }
                    }
                    if (clear_cnt == 0)
                    {
                        // printf("Cleaning is done.\n"); fflush(stdout);
                        clean_tail = false;
                    }
                }
            }

            cnt = 0;
            for (auto &e1 : sorted_nth_nbf)
            {
                for (auto &e2 : e1.second)
                {
                    // for(auto e : e2.second){
                    //   std::cout << "(" << e1.first << " " << e2.first << " " << e << ") ";
                    //   fflush(stdout);
                    // }
                    // std::cout << std::endl;
                    int nbf_cnt = e2.second.size();
                    long cnt_diff = e1.first * nbf_cnt;
                    long cnt_next = cnt + cnt_diff;
                    double prev_ratio = cnt * 1.0 / cnt_next;
                    double new_ratio = cnt_diff * 1.0 / cnt_next;
                    // std::cout << dec << cnt << " " << cnt_diff << " " <<cnt_next << " " << prev_ratio << " " << new_ratio << std::endl;
                    nth_common_case[phase_number] =
                        (nth_common_case[phase_number].value() * prev_ratio) + (e2.first * new_ratio);

                    double avgnbf = 0;
                    for (auto e : e2.second)
                        avgnbf += (e * (1.0 / nbf_cnt));
                    // std::cout << dec << avgnbf << " " << nbf_common_case[phase_number].value() << " -> ";
                    nbf_common_case[phase_number] =
                        (nbf_common_case[phase_number].value() * prev_ratio) + (avgnbf * new_ratio);
                    // std::cout << dec << nbf_common_case[phase_number].value()<< std::endl;
                    cnt = cnt_next;
                }
            }

            // std::cout << "=========" << comp_name << ":" << phase_number << "=========" << std::endl << std::endl << std::endl;

            //
            //
            //   weighted_avg = weighted_avg * ((total_cnt - e.second) * 1.0 / total_cnt)
            //                + ((e.first * e.second) * 1.0 / total_cnt);
            //
            //   if (first) {
            //     min_nth[this->phase_number] = e.first;
            //     first = false;
            //   }
            //   max_nth[this->phase_number] = e.first;
            // }
            // avg_nth[this->phase_number] = weighted_avg;

            bool covered_10_percentile = false;
            long long cum_cnt = 0;
            for (auto &e : this->nth_distr)
            {
                cum_cnt += e.second;
                if (!covered_10_percentile && cum_cnt >= total_cnt * 0.1)
                {
                    covered_10_percentile = true;
                    min_nth_90_percentile[this->phase_number] = e.first;
                }
                if (cum_cnt >= total_cnt * 0.9)
                {
                    max_nth_90_percentile[this->phase_number] = e.first;
                    break;
                }
            }
        }

        outfile1.close();
        outfile2.close();
        outfile3.close();
    }
#endif

    float RowhammerDefense::get_throttling_coeff(int row_id, int coreid, bool is_real_hammer)
    {
        if (this->method == ROWHAMMER_DEFENSE::BLOCKHAMMER && this->blockhammer_dryrun == 0)
        {
            float room = (float)(blacklisted_act_budget - hammer_cnts[active_bloom_filter][coreid]);
            float throttle_coeff = room / blacklisted_act_budget;

            if (throttle_coeff < this->throttle_threshold)
            {
                if (is_real_hammer)
                    this->coreblock_truepositives[this->phase_number]++;
                else
                    this->coreblock_falsepositives[this->phase_number]++;
                return throttle_coeff;
            }
            else
            {
                if (is_real_hammer)
                    this->coreblock_falsenegatives[this->phase_number]++;
                else
                    this->coreblock_truenegatives[this->phase_number]++;
                return 1.0;
            }
        }
        return 1.0;
    }

    // This function is called before issuing a row activation.
    // If the row is blacklisted and recently activated, the function returns the clock cycle until when the activation needs to be stalled
    // If the activation is ok to issue, the function returns -1, so that the current clock will be greater than it.
    long RowhammerDefense::is_rowhammer_safe(int row_id, long clk, bool is_real_hammer, int coreid)
    {
        this->clk = clk;
        switch (this->method)
        {
        case ROWHAMMER_DEFENSE::BLOCKHAMMER:
        {
            if (clk - bf_start_time[active_bloom_filter] > this->nREFW / this->n_bf_window)
            {
                // tCBF has passed; the active filter should change.
                bf[active_bloom_filter].clear();
                bf_start_time[active_bloom_filter] = clk;
                append_hammer_probs_file();
                active_bloom_filter = 1 - active_bloom_filter;
            }

            bool bf_response = bf[active_bloom_filter].test(row_id);
            if (bf_response && this->blockhammer_dryrun == 0) // the row is blacklisted
            {
                long blocked_until = this->does_blockhammer_approve(row_id, clk, is_real_hammer);
                return blocked_until;
            }
            else
            {
#ifdef BHSTATS // Keep a record of the nonblocked row activations from benign and attack traces
                if (this->nonblocked_rows.find(row_id) == this->nonblocked_rows.end())
                    this->nonblocked_rows[row_id] = make_pair(1, (int)is_real_hammer);
                else
                    this->nonblocked_rows[row_id].first++;
#endif
                return -1;
            }
        }
        default:
            return -1;
        }
    }

    long RowhammerDefense::does_blockhammer_approve(int row_id, long clk, bool is_real_hammer)
    {
        long ret_val = 0; // 0 means approves
        long blocked_until = 0;
        int cnt = 0;
        int most_recent_to_remove = -1;
        int latest_timestamp = -1;
        for (auto entry : this->last_activates)
        {
            long time_delta = clk - entry.timestamp;
            if (time_delta > this->t_delay)
            {
                most_recent_to_remove++;
            }
            else
            {
                if (entry.row_id == row_id)
                {
                    cnt++;
                    latest_timestamp = (latest_timestamp < entry.timestamp) ? entry.timestamp : latest_timestamp; //+ this->t_delay + 1;
                }
            }
        }
        if (latest_timestamp > 0)
            blocked_until = latest_timestamp + this->t_delay + 1;
        if (cnt > 0)
        {
            this->num_blocked_acts[this->phase_number]++;
            { // keep a record of the blocked rows.
#ifdef BHSTAT
                if (this->blocked_rows.find(row_id) == this->blocked_rows.end())
                    this->blocked_rows[row_id] = make_pair(0, (int)is_real_hammer);
                this->blocked_rows[row_id].first++;
#endif
            }
            ret_val = blocked_until;
        }
        else
        { // keep a record of the nonblocked rows.
#ifdef BHSTAT
            if (this->nonblocked_rows.find(row_id) == this->nonblocked_rows.end())
                this->nonblocked_rows[row_id] = make_pair(0, (int)is_real_hammer);
            this->nonblocked_rows[row_id].first++;
#endif
        }
        if (most_recent_to_remove >= 0)
        {
            most_recent_to_remove = (most_recent_to_remove < this->last_activates.size()) ? most_recent_to_remove : this->last_activates.size();
            this->last_activates.erase(
                this->last_activates.begin(),
                this->last_activates.begin() + most_recent_to_remove);
        }
        return ret_val;
    }

    // This function is called in Controller::issue_cmd, only if the issued command is an ACT.
    // Blockhammer records the issued ACT into it's window.
    // PARA flips a coin and returns a victim row address to activate later on.
    // RowHammerDefense (this) updates the stats with the issued ACT.
    int RowhammerDefense::get_row_to_refresh(int row_id, long clk, int adj_row_refresh_cnt, bool is_real_hammer, int coreid)
    {
        int adj_row_id = -1;
        long mrloc_1;
        long mrloc_2;
        switch (this->method)
        {
        case ROWHAMMER_DEFENSE::PARA:
        {
            if (adj_row_refresh_cnt != 0)
                break;
            int rand_number = rand_r(&para_seed);
            if ((rand_number % 1000) / 1000.0 < this->para_threshold)
            {
                adj_row_id = row_id + ((para_above) ? 1 : -1);
                para_above = !para_above;
                // rows_to_refresh.push_back(adj_row_id);
                this->num_issued_refs[this->phase_number]++;
            }
            break;
        }
        case ROWHAMMER_DEFENSE::GRAPHENE:
        {
            // First, check if reset time is up:
            if (clk >= graphene.reset_time)
            {
                graphene_table_rows.resize(graphene.Nentry, -1);
                graphene_table_cnts.resize(graphene.Nentry, 0);
                graphene_spillover_cnt = 0;
                graphene.reset_time = clk + this->nREFW / graphene.k;
                std::cout << graphene.reset_time << std::endl;
            }
            if (adj_row_refresh_cnt >= this->blast_radius * 2)
                break;
            // Is the row already in table?
            auto row_it = find(graphene_table_rows.begin(), graphene_table_rows.end(), row_id);
            if (row_it != graphene_table_rows.end())
            {
                // it is a hit
                int index = row_it - graphene_table_rows.begin();
                // increment the corresponding counter
                if (adj_row_refresh_cnt == 0)
                    graphene_table_cnts[index] = graphene_table_cnts[index] + 1;

                if (graphene_table_cnts[index] % graphene.T == 0)
                {
                    int adj_row_offset = ((adj_row_refresh_cnt / 2) + 1) * pow(-1, adj_row_refresh_cnt % 2);
                    adj_row_id = row_id + adj_row_offset;
                    this->num_issued_refs[this->phase_number]++;
                }
            }
            else
            { // the activated row does not exist in the table.
                // any entry with the same value as the spillover count?
                auto cnt_it = find(graphene_table_cnts.begin(), graphene_table_cnts.end(), graphene_spillover_cnt);
                if (cnt_it != graphene_table_cnts.end())
                { // yes there is a row entry as much as the spillover count
                    int index = cnt_it - graphene_table_cnts.begin();
                    // replace the row address in the corresponding entry
                    graphene_table_rows[index] = row_id;
                    graphene_table_cnts[index] = graphene_table_cnts[index] + 1;
                    if (graphene_table_cnts[index] % graphene.T == 0)
                    {
                        adj_row_id = row_id + 1;
                        this->num_issued_refs[this->phase_number]++;
                    }
                }
                else
                { // the row does not exist in the table, and spillover is not large enough
                    graphene_spillover_cnt++;
                }
            }
            break;
        }

        case ROWHAMMER_DEFENSE::BLOCKHAMMER:
        {
            if (adj_row_refresh_cnt != 0)
                break;
            int passive_count = bf[1 - active_bloom_filter].insert(row_id);
            bf[active_bloom_filter].insert(row_id);
            if (bf[active_bloom_filter].test(row_id))
            {
                hammer_cnts[active_bloom_filter][coreid]++;
            }

            debug("Check bloom filter refresh");
            debug("passive_count %d", passive_count);
            debug("active bloom filter %d", active_bloom_filter);
            debug("start time %d", bf_start_time[active_bloom_filter]);
            debug("nCBF %d", this->nREFW / this->n_bf_window);
            if ((passive_count > this->blockhammer_nbf / 2) ||
                (clk - bf_start_time[active_bloom_filter] > this->nREFW / this->n_bf_window))
            { // switch filters
                append_hammer_probs_file();
                bf[active_bloom_filter].clear();
                bf_start_time[active_bloom_filter] = clk;
                for (int i = 0; i < num_cores; i++)
                {
                    hammer_cnts[active_bloom_filter][i] = 0;
                }
                active_bloom_filter = 1 - active_bloom_filter;
                debug("bloom filter refreshed");
            }
            break;
        }

        case ROWHAMMER_DEFENSE::TWICE:
            if (adj_row_refresh_cnt > 1)
                break;
            if (this->twice_table.find(row_id) != twice_table.end())
            {
                if (this->twice_table[row_id].valid)
                {
                    if (this->twice_table[row_id].act_cnt >= this->twice_threshold)
                    {
                        adj_row_id = row_id + ((adj_row_refresh_cnt == 0) ? 1 : -1);
                        if (adj_row_refresh_cnt == 1)
                            this->twice_table.erase(this->twice_table.find(row_id));
                        this->num_issued_refs[this->phase_number]++;
                    }
                    else
                    {
                        this->twice_table[row_id].act_cnt += 1;
                    }
                }
            }
            else
            {
                twice_table_entry entry;
                this->twice_table.insert(pair<int, twice_table_entry>(row_id, entry));
                this->twice_table[row_id].valid = true;
                this->twice_table[row_id].life = 0;
                this->twice_table[row_id].act_cnt = 1;
            }
            break;

            // CBT, Rocky #begin

        case ROWHAMMER_DEFENSE::CBT:
            if (adj_row_refresh_cnt == last_set_counter_population)
            {
                last_set_counter_population = -1;
                break;
            }

            if (adj_row_refresh_cnt < last_set_counter_population && adj_row_refresh_cnt != 0)
            {
                if (adj_row_refresh_cnt == cbt_counters_per_bank[last_iterator].upper_limit - 1)
                {
                    cbt_counters_per_bank[last_iterator].counter_value = 0;
                    last_set_counter_population = -1;
                    adj_row_id = -1;
                    break;
                }
                adj_row_id = (int)cbt_counters_per_bank[last_iterator].lower_limit + adj_row_refresh_cnt - 1;
                break;
            }

            int iterator;

            for (iterator = 0; iterator < cbt_counter_no; ++iterator)
            {
                if (row_id < cbt_counters_per_bank[iterator].upper_limit && row_id > cbt_counters_per_bank[iterator].lower_limit)
                {
                    last_iterator = iterator;
                    last_set_counter_population = cbt_counters_per_bank[iterator].upper_limit - cbt_counters_per_bank[iterator].lower_limit + 1;
                    if (cbt_counters_per_bank[iterator].counter_value < cbt_thresholds[cbt_counters_per_bank[iterator].counter_level] || (cbt_counters_per_bank[iterator].counter_value <= cbt_thresholds[cbt_counters_per_bank[iterator].counter_level] && cbt_thresholds[cbt_counters_per_bank[iterator].counter_level] == 0))
                    {
                        cbt_counters_per_bank[iterator].counter_value++;
                        adj_row_id = -1;
                        break;
                    }
                    else if (cbt_counters_per_bank[iterator].counter_level == cbt_total_levels - 1)
                    {
                        cbt_counters_per_bank[iterator].counter_value = 0;
                        if (adj_row_refresh_cnt == cbt_counters_per_bank[iterator].upper_limit - 1)
                        {
                            adj_row_id = -1;
                            break;
                        }
                        adj_row_id = (int)cbt_counters_per_bank[iterator].lower_limit + adj_row_refresh_cnt - 1;
                        break;
                    }
                    else if (cbt_counters_per_bank[iterator].counter_level < cbt_total_levels - 1)
                    {
                        if (last_activated < cbt_counter_no - 1 && cbt_counters_per_bank[iterator].counter_level < cbt_total_levels - 1)
                        {
                            last_activated++;
                            cbt_counters_per_bank[last_activated].upper_limit = cbt_counters_per_bank[iterator].upper_limit;
                            cbt_counters_per_bank[last_activated].counter_value = cbt_counters_per_bank[iterator].counter_value;
                            cbt_counters_per_bank[iterator].upper_limit = ((cbt_counters_per_bank[iterator].upper_limit - cbt_counters_per_bank[iterator].lower_limit + 1) / (2)) + cbt_counters_per_bank[iterator].lower_limit;
                            cbt_counters_per_bank[last_activated].lower_limit = cbt_counters_per_bank[iterator].upper_limit + 1;
                            cbt_counters_per_bank[iterator].counter_level++;
                            cbt_counters_per_bank[last_activated].counter_level = cbt_counters_per_bank[iterator].counter_level;
                            adj_row_id = -1;
                            break;
                        }
                        else if (last_activated == cbt_counter_no - 1)
                        {
                            for (int i = 0; i < cbt_counter_no; ++i)
                            {
                                cbt_counters_per_bank[i].counter_level = cbt_total_levels - 1;
                                adj_row_id = -1;
                                break;
                            }
                        }
                    }
                    break;
                }
            }
            break;
            // CBT, Rocky #end

        case ROWHAMMER_DEFENSE::PROHIT:

            if (adj_row_refresh_cnt != 0)
                break;
            pro_hit_update(&prh, row_id, row_id + 1);
            pro_hit_update(&prh, row_id, row_id - 1);
            if (prh.hot_rows.size() == prh.hot_entries)
            {

                adj_row_id = prh.hot_rows.front();
                this->num_issued_refs[this->phase_number]++;
                prh.hot_rows.pop_front();
            }
            break;

        case ROWHAMMER_DEFENSE::MRLOC:

            if (adj_row_refresh_cnt > 1)
                break;
            if (adj_row_refresh_cnt == 0)
            {
                mrloc_1 = mrloc_update(&mrloc, row_id, row_id + 1);
                mrloc_2 = mrloc_update(&mrloc, row_id, row_id - 1);

                if (mrloc_1 != -1)
                    adj_row_id = mrloc_1;
                else if (mrloc_2 != -1)
                    adj_row_id = mrloc_2;
                else
                    adj_row_id = -1;
            }
            else
            {
                if (mrloc_2 != 1)
                    adj_row_id = mrloc_2;
                else
                    adj_row_id = -1;
            }
            break;

        default:
            break;
        }
        if (adj_row_refresh_cnt == 0)
        {
            this->num_issued_acts[this->phase_number]++;
            this->append_act(row_id, clk, false, is_real_hammer);
        }
        return adj_row_id;
    }

    int RowhammerDefense::refresh_tick(long clk)
    {
        int retval = 0;
        if (clk > this->next_clk_to_dump)
        {
            this->next_clk_to_dump += this->nREFW;
#ifdef COLLECT_ROWACTCNT
            this->dump_rhli_per_row();
            this->dump_rhli_hist();
#endif
        }
        switch (this->method)
        {
        case ROWHAMMER_DEFENSE::TWICE:
            for (std::map<int, twice_table_entry>::iterator iterator = this->twice_table.begin(); iterator != this->twice_table.end(); ++iterator)
            {
                if (iterator->second.life > (iterator->second.act_cnt / twice_pruning_interval_threshold))
                {
                    this->twice_table.erase(iterator);
                }
                else
                    iterator->second.life++;
            }

        case ROWHAMMER_DEFENSE::CBT:

            if (partial_refresh_counter == 8238)
            {
                for (int iterator = 0; iterator < this->cbt_counter_no; ++iterator)
                {
                    partial_refresh_counter = 0;
                    this->cbt_counters_per_bank[iterator].counter_value = 0;
                    this->cbt_counters_per_bank[iterator].counter_level = 0;
                    this->cbt_counters_per_bank[iterator].upper_limit = 0;
                    this->cbt_counters_per_bank[iterator].lower_limit = 0;
                    last_activated = 0;
                    if (iterator == 0)
                    {
                        this->cbt_counters_per_bank[iterator].upper_limit = this->cbt_rows_per_bank - 1;
                    }
                }
            }
            else
            {
                partial_refresh_counter++;
            }
            break;

        default:
            break;
        }
        for (int row_id = refresh_pointer; row_id < refresh_pointer + ref_batch_sz; row_id++)
        {
            this->append_act(row_id, clk, true, false);
        }
        refresh_pointer = (refresh_pointer + ref_batch_sz) % num_total_rows;
        return retval;
    }

#ifdef COLLECT_ROWACTCNT
    void update_rhli_stats(int row_id, long clk)
    {
#ifdef DEBUG
        cerr << "updating the rhli stats for row " << row_id << " @ clk " << clk << "." << std::endl;
#endif
        if (rhli_rows.find(row_id) == rhli_rows.end())
        { // this is the first time we activate this row.
#ifdef DEBUG
            cerr << "this is the first time I'm seeing " << row_id << "." << std::endl;
#endif
            rhli_rows[row_id] = {1, clk};
        }
        else
        {
            long first_access = rhli_rows[row_id].first_access;
            int act_cnt = rhli_rows[row_id].act_cnt;
#ifdef DEBUG
            cerr << "here is my record for row " << row_id << ":" << std::endl
                 << "  first accessed @ clk " << first_access << std::endl
                 << "  activated for " << act_cnt << "times." << std::endl;
#endif
            if (clk - first_access > nREFW)
            { // it has been more than a refresh window since the first activation
// first: aggregate the stats from the prev refresh window
#ifdef DEBUG
                cerr << "  oops it's too old. Resetting the act count and updating the histogram." << std::endl;
#endif
                if (rhli_act_cnts.find(act_cnt) == rhli_act_cnts.end())
                {
                    rhli_act_cnts[act_cnt] = 1;
                }
                else
                {
                    rhli_act_cnts[act_cnt]++;
                }
                // second: start counting for a new window
                rhli_rows[row_id] = {1, clk};
            }
            else
            { // we are still in the same refresh window, just keep counting
#ifdef DEBUG
                cerr << "  updating act counts to " << rhli_rows[row_id].act_cnt + 1 << std::endl;
#endif
                rhli_rows[row_id].act_cnt = act_cnt + 1;
            }
        }
    }
#endif

    void RowhammerDefense::append_act(int row_id, long clk, bool is_ref, bool is_real_hammer)
    {
        // Blockhammer watches you, even asleep
        switch (this->method)
        {
        case ROWHAMMER_DEFENSE::BLOCKHAMMER:
            // case ROWHAMMER_DEFENSE::BLOOM_FILTERED_BLOCKHAMMER:
            // case ROWHAMMER_DEFENSE::CORRECTED_BLOCKHAMMER:
            // case ROWHAMMER_DEFENSE::BLOCKHAMMER_TOLERANT:
            if (this->blockhammer_dryrun == 0)
            {
                this->last_activates.push_back((ActWindowEntry){row_id, clk});
            }
            break;
        default:
            break;
        }
#ifdef COLLECT_ROWACTCNT
        update_rhli_stats(row_id, clk);
#endif
        // Also observe the ground-truth
        // First, record the time delta between this activate and the previous one
#ifdef COLLECT_ROWSTATES
        this->glob_act_cnt++;
        if (!this->act_logs[row_id].empty())
        {
            long last_act = this->act_logs[row_id].back();
            long act_interval = (clk - last_act); // / this->nRC;
            // printf("[%ld] Row %d is active again after %ld tRCs.\n",clk, row_id, act_interval);
            if (this->row_states.find(row_id) == this->row_states.end())
            {
                this->row_states[row_id] = make_pair(last_act, ROWSTATE::CLOSED);
            }
            ROWSTATE old_state = this->row_states[row_id].second;
            ROWSTATE new_state = (act_interval < this->min_safe_activation_interval) ? ROWSTATE::OPENED : ROWSTATE::CLOSED;

            if (new_state != old_state)
            {
                long state_start = this->row_states[row_id].first;
                long duration = (last_act - state_start); // / this->nRC;
                // printf("      Row %d is changing state from %d to %d after %ld clks.\n",
                //   row_id, (int) old_state, (int) new_state, duration);
                if (duration > 0)
                {
                    if (this->state_length_distr[old_state].find(duration) == this->state_length_distr[old_state].end())
                    {
                        this->state_length_distr[old_state][duration] = 1;
                    }
                    else
                    {
                        this->state_length_distr[old_state][duration] += 1;
                    }
                }
                this->row_states[row_id] = make_pair(last_act, new_state);

                // update nth histogram
                if (new_state == ROWSTATE::CLOSED)
                {
                    if (this->nth_distr.find(this->hammer_cnt[row_id]) == this->nth_distr.end())
                    {
                        this->nth_distr[this->hammer_cnt[row_id]] = 1;
                    }
                    else
                    {
                        this->nth_distr[this->hammer_cnt[row_id]] += 1;
                    }
                    // this->hammer_cnt[row_id] = 0;
                }

                // update nbf histogram
                if (new_state == ROWSTATE::OPENED)
                {
                    if (this->last_hammer_start.find(row_id) != this->last_hammer_start.end())
                    {
                        long long h2h_act_cnt = this->glob_act_cnt - this->last_hammer_start[row_id];
                        // std::cout << "[GlobACT: " << dec << this->glob_act_cnt << "] ";
                        // std::cout << "Last hammer for row "<< dec << row_id << " was at act number: ";
                        // std::cout << dec << this->last_hammer_start[row_id];
                        // std::cout << " Nbf: " << dec << h2h_act_cnt << " ACTs" << std::endl;
                        if (this->nbf_distr.find(h2h_act_cnt) == this->nbf_distr.end())
                        {
                            this->nbf_distr[h2h_act_cnt] = 1;
                        }
                        else
                        {
                            this->nbf_distr[h2h_act_cnt] += 1;
                        }

                        long hcnt = this->hammer_cnt[row_id];
                        long hratio = (long)round(h2h_act_cnt * 1.0 / hcnt);
                        if (this->nth_nbf_distr.find(hcnt) == this->nth_nbf_distr.end() || this->nth_nbf_distr[hcnt].find(hratio) == this->nth_nbf_distr[hcnt].end())
                        {
                            this->nth_nbf_distr[hcnt][hratio] = 1;
                        }
                        else
                        {
                            this->nth_nbf_distr[hcnt][hratio] += 1;
                        }
                    }
                    this->hammer_cnt[row_id] = 2; // because we detect hammering in second activate
                    this->last_hammer_start[row_id] = this->glob_act_cnt;
                    // std::cout << "New hammering starts for row " << dec << row_id << std::endl;
                }
            }

            // collect stats of number of hot rows at a given time
            // (i.e., how many rows are being hammered simultaneously)
            {
                // std::cout << "clk: " << dec << clk << " row: " << dec << row_id << std::endl;
                // std::cout << "  rowstates:" << std::endl;
                int cnt = 0;
                for (auto &entry : this->row_states)
                {
                    // std::cout << "  " << dec << entry.first << "," << dec << entry.second.first << "," << entry.second.second;
                    if (entry.second.second == ROWSTATE::OPENED)
                    {
                        // std::cout << " --- was being hammered";
                        if (clk - this->act_logs[entry.first].back() <= this->min_safe_activation_interval)
                        {
                            // std::cout << ", and still being hammered";
                            cnt++;
                        }
                    }
                    // std::cout << std::endl;
                }
                // std::cout << dec << cnt << " rows are being hammered at this clk cycle." << std::endl;
                if (this->num_hot_rows.find(cnt) == this->num_hot_rows.end())
                {
                    this->num_hot_rows[cnt] = 1;
                }
                else
                {
                    this->num_hot_rows[cnt] += 1;
                }

                // Count hammering activates per row
                if (new_state == ROWSTATE::OPENED)
                {
                    if (this->hammer_cnt.find(row_id) == this->hammer_cnt.end())
                    {
                        this->hammer_cnt[row_id] = 2; // this is two because we detect hammering behavior at the second activate.
                    }
                    else
                    {
                        this->hammer_cnt[row_id] += 1;
                    }
                }
            }

            if (this->act_intervals.find(act_interval) == this->act_intervals.end())
            {
                // printf("      Oh wow! This is new!\n");
                this->act_intervals[act_interval] = 1;
            }
            else
            {
                // printf("      I saw this activation interval %ld times before.\n", this->act_intervals[act_interval]);
                this->act_intervals[act_interval] += 1;
            }
            // printf("      To sum up, count of this activation interval is %ld.\n", this->act_intervals[act_interval]);
        }
        else
        {
            this->row_states[row_id] = make_pair(clk, ROWSTATE::CLOSED);
            // printf("[%ld] There is no record of any activates.\n", clk);
        }
#endif
        // Second, append the new ACT to the timestamp queue of a relevant queue.
        // this->act_logs[row_id].push_back(clk);
    }

    long RowhammerDefense::mrloc_update(struct mrloc *mrloc, long row, long neighbor)
    {
        int index_hit = -1;
        int counter = 0;
        for (std::deque<long>::iterator it = mrloc->mrloc_queue.begin(); it != mrloc->mrloc_queue.end(); ++it)
        {
            if (*it == neighbor)
            {
                index_hit = counter;
                break;
            }
            counter++;
        }

        if (index_hit == -1)
        {
            mrloc->mrloc_queue.push_front(neighbor);
            if (mrloc->mrloc_queue.size() > mrloc->size)
            {
                mrloc->mrloc_queue.pop_back();
            }
            double prob;
            prob = 0.0005;
            if ((rand() % 1000 / 1000.0) < prob)
                return neighbor;
            else
                return -1;
        }

        else
        {
            mrloc->mrloc_queue.push_front(neighbor);
            if (mrloc->mrloc_queue.size() > mrloc->size)
            {
                mrloc->mrloc_queue.pop_back();
            }
            double prob;
            prob = 0.0005 + 0.0005 * (mrloc->size - index_hit + 1);
            if ((rand() % 1000 / 1000.0) < prob)
                return neighbor;
            else
                return -1;
        }
    }

    void RowhammerDefense::pro_hit_update(struct prohit *prh, long row, long neighbor)
    {
        int index_hit = -1;
        int counter = 0;
        for (std::deque<long>::iterator it = prh->hot_rows.begin(); it != prh->hot_rows.end(); ++it)
        {
            if (*it == neighbor)
            {
                index_hit = counter;
            }
            counter++;
        }

        for (std::deque<long>::iterator it = prh->cold_rows.begin(); it != prh->cold_rows.end(); ++it)
        {
            if (*it == neighbor)
            {
                index_hit = counter;
            }
            counter++;
        }

        // long temp;
        if (index_hit == -1)
        {
            if ((rand() % 1000 / 1000.0) < prh->pr_insert_thres)
            {
                prh->cold_rows.push_front(neighbor);
                if (prh->cold_rows.size() > prh->cold_entries)
                {
                    int temp;
                    temp = (rand() % prh->cold_rows.size());
                    prh->cold_rows.erase(prh->cold_rows.begin() + temp);
                }
            }
        }
        else
        {
            long temp;
            if (index_hit <= prh->hot_entries)
            {
                temp = prh->hot_rows[index_hit - 1];
                if (index_hit != 0 && prh->hot_rows.size() > 1)
                {
                    prh->hot_rows[index_hit - 1] = prh->hot_rows[index_hit];
                    prh->hot_rows[index_hit] = temp;
                }
            }
            else
            {
                long temp2;
                temp = prh->cold_rows[index_hit - prh->hot_entries];
                prh->cold_rows.erase(prh->cold_rows.begin() + index_hit - prh->hot_entries);
                if (prh->hot_rows.size() == prh->hot_entries)
                {
                    temp2 = prh->hot_rows.back();
                    prh->hot_rows.pop_back();
                    prh->cold_rows.push_front(temp2);
                    prh->hot_rows.push_back(temp);
                }
                else
                {
                    prh->hot_rows.push_back(temp);
                }
            }
        }
    }
}

/*
  [1] Kim et al. "Flipping Bits in Memory Without Accessing Them:
      An Experimental Study of DRAM Disturbance Errors," ISCA 2014
*/
