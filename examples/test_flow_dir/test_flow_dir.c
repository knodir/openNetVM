/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2019 George Washington University
 *            2015-2019 University of California Riverside
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * The name of the author may not be used to endorse or promote
 *       products derived from this software without specific prior
 *       written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  test_flow_dir.c - an example using onvm_flow_dir_* APIs.
 *  Ack: interactive CLI is adopted from LSH (with The Unlicense) at 
 *  https://brennan.io/2015/01/16/write-a-shell-in-c/
 ********************************************************************/

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/wait.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_memzone.h>

#include "onvm_flow_dir.h"
#include "onvm_flow_table.h"
#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"
#include "onvm_sc_common.h"
#include "onvm_sc_mgr.h"

#define NF_TAG "test_flow_dir"

extern struct onvm_ft *sdn_ft;

/* number of package between each print */
static uint32_t print_delay = 1000000;

static uint32_t destination;

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage:\n");
        printf("%s [EAL args] -- [NF_LIB args] -- -d <destination> -p <print_delay>\n", progname);
        printf("%s -F <CONFIG_FILE.json> [EAL args] -- [NF_LIB args] -- [NF args]\n\n", progname);
        printf("Flags:\n");
        printf(" - `-d <dst>`: destination service ID to foward to\n");
        printf(" - `-p <print_delay>`: number of packets between each print, e.g. `-p 1` prints every packets.\n");
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c;

        while ((c = getopt(argc, argv, "d:p:")) != -1) {
                switch (c) {
                        case 'd':
                                destination = strtoul(optarg, NULL, 10);
                                break;
                        case 'p':
                                print_delay = strtoul(optarg, NULL, 10);
                                break;
                        case '?':
                                usage(progname);
                                if (optopt == 'd')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                                else if (optopt == 'p')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                                else if (isprint(optopt))
                                        RTE_LOG(INFO, APP, "Unknown option `-%c'.\n", optopt);
                                else
                                        RTE_LOG(INFO, APP, "Unknown option character `\\x%x'.\n", optopt);
                                return -1;
                        default:
                                usage(progname);
                                return -1;
                }
        }
        return optind;
}

/*
 * This function displays stats. It uses ANSI terminal codes to clear
 * screen when called. It is called from a single non-master
 * thread in the server process, when the process is run with more
 * than one lcore enabled.
 */
static void
do_stats_display(struct rte_mbuf *pkt) {
        const char clr[] = {27, '[', '2', 'J', '\0'};
        const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
        static uint64_t pkt_process = 0;
        struct ipv4_hdr *ip;

        pkt_process += print_delay;

        /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);

        printf("PACKETS\n");
        printf("-----\n");
        printf("Port : %d\n", pkt->port);
        printf("Size : %d\n", pkt->pkt_len);
        printf("N°   : %" PRIu64 "\n", pkt_process);
        printf("\n\n");

        ip = onvm_pkt_ipv4_hdr(pkt);
        if (ip != NULL) {
                onvm_pkt_print(pkt);
        } else {
                printf("No IP4 header found\n");
        }
}

static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
        static uint32_t counter = 0;
        struct onvm_flow_entry *flow_entry = NULL;
        int ret;
        
        // printf("--- bar\n");

        if (++counter == print_delay) {
                do_stats_display(pkt);
                counter = 0;
        }

        ret = onvm_flow_dir_get_pkt(pkt, &flow_entry);
        if (ret >= 0) {
                meta->action = ONVM_NF_ACTION_NEXT;
                printf("meta->action = %d\n", meta->action);
                //exit(0);
        } else {
                ret = onvm_flow_dir_add_pkt(pkt, &flow_entry);
                if (ret < 0) {
                        meta->action = ONVM_NF_ACTION_DROP;
                        meta->destination = 0;
                        return 0;
                }
                memset(flow_entry, 0, sizeof(struct onvm_flow_entry));
                flow_entry->sc = onvm_sc_create();
                onvm_sc_append_entry(flow_entry->sc, ONVM_NF_ACTION_TONF, destination);
                onvm_sc_print(flow_entry->sc);
        }
        return 0;
}

static char*
lsh_read_line(void) {
        int nchars_read; 
        char *line = NULL;
        size_t bufsize = 0; // have getline allocate a buffer for us
        nchars_read = getline(&line, &bufsize, stdin);
        if (nchars_read == EINVAL) {
                perror("Invalid input\n");
                exit(EXIT_FAILURE);
        }
        return line;
}


#define LSH_TOK_BUFSIZE 64
#define ADD_LEN 7
#define DEL_LEN 6
#define LSH_TOK_DELIM " \t\r\n\a"
#define EQ_TOK_DELIM "="
/**
   @brief Split a line into tokens (very naively).
   @param line The line.
   @return Null-terminated array of tokens.
 */
static char**
lsh_split_line(char *line) {
        int bufsize = LSH_TOK_BUFSIZE, position = 0;
        char **tokens = malloc(bufsize * sizeof(char*));
        char *token;

        if (!tokens) {
                printf("lsh: allocation error\n");
                exit(EXIT_FAILURE);
        }

        token = strtok(line, LSH_TOK_DELIM);
        while (token != NULL) {
                tokens[position] = token;
                position++;

                if (position >= bufsize) {
                        bufsize += LSH_TOK_BUFSIZE;
                        tokens = realloc(tokens, bufsize * sizeof(char*));
                        if (!tokens) {
                                perror("token allocation error\n");
                                exit(EXIT_FAILURE);
                        }
                }

                token = strtok(NULL, LSH_TOK_DELIM);
        }
        tokens[position] = NULL;
        return tokens;
}

/**
   @brief Split a string into tokens with equal delimiter.
   @param whole_str The string to tokenize.
   @return Null-terminated array of tokens.
 */
static char**
split_to_tokens(char *whole_str) {
        int bufsize = LSH_TOK_BUFSIZE, position = 0;
        char **tokens = malloc(bufsize * sizeof(char*));
        char *token;

        if (!tokens) {
                perror("allocation error\n");
                exit(EXIT_FAILURE);
        }

        token = strtok(whole_str, EQ_TOK_DELIM);
        while (token != NULL) {
                tokens[position] = token;
                position++;

                if (position >= bufsize) {
                        bufsize += LSH_TOK_BUFSIZE;
                        tokens = realloc(tokens, bufsize * sizeof(char*));
                        if (!tokens) {
                                perror("token allocation error\n");
                                exit(EXIT_FAILURE);
                        }
                }

                token = strtok(NULL, LSH_TOK_DELIM);
        }
        tokens[position] = NULL;
        return tokens;
}

static void
cli_help(void) {
        printf("TBD help\n");
}

static int
len(char **ptr) {
        int count = 0;
        while (ptr[count] != NULL) {
                count += 1;
        }
        return count;
}

static int
add_ft_entry(char **args) {
        char **tokens;
        int i = 0, kv_len = 2;
        int argc = len(args);
        printf("argc = %d\n", argc);
        for (i = 0; i < argc; i++) {
                printf("%s\n", args[i]);
        }
        if (argc != 7) {
                printf("invalid length (%d), should be %d", argc, ADD_LEN);
                return 0;
        }
        // skip args[0] since it is just "add" command
        for (i = 1; i < argc; i++) {
                tokens = split_to_tokens(args[i]);
                if (len(tokens) != kv_len) {
                        printf("invalid key-value length (%d), should be %d", len(tokens), kv_len);
                        return 0;
                }
                printf("tokens[0] = %s, tokens[1] = %s\n", tokens[0], tokens[1]);
                free(tokens);
        }
        // add src-ip=1.2.3.4 dst-ip=1.2.3.5 src-port=42 dst-port=42 proto=tcp next-sc=1
        return 0;
}

// /*Struct that holds all NF state information */
// struct state_info {
//         struct onvm_ft *ft;
//         uint16_t destination;
//         uint16_t print_delay;
//         uint16_t num_stored;
//         uint64_t elapsed_cycles;
//         uint64_t last_cycles;
// };
// 
// /*Struct that holds info about each flow, and is stored at each flow table entry */
// struct flow_stats {
//         int pkt_count;
//         uint64_t last_pkt_cycles;
//         int is_active;
// };
// 
// struct state_info *state_info;


static void
show_flow_table(void) {
        struct flow_stats *data = NULL;
        struct onvm_ft_ipv4_5tuple *key = NULL;
        uint32_t next = 0;
        int32_t index;
        struct onvm_flow_entry *flow_entry;
        int entry = 0, ret = 0, i = 0;

        printf("------------------------------\n");
        printf("     Flow Table Contents\n");
        printf("------------------------------\n");
        // sdn_ft is initialized by onvm_flow_dir_nf_init();
        while ((index = onvm_ft_iterate(sdn_ft, (const void **)&key, (void **)&data, &next)) > -1) {
                printf("Entry #%d. ", entry);
                // printf("index = %d, next = %d, pkt_count = %d\n", index, next, data->pkt_count);
                _onvm_ft_print_key(key);
                ret = onvm_flow_dir_get_key(key, &flow_entry);
                if (ret < 0) {
                        perror("failed to get flow_entry for: ");
                        _onvm_ft_print_key(key);
                        exit(EXIT_FAILURE);
                }
                if (flow_entry != NULL) {
                        printf("The length of the chain bound on this 5-tuple is %d\n",
                                flow_entry->sc->chain_length);
                        for (i = 0; i < flow_entry->sc->chain_length; i++) {
                                printf("NF #%d has destination #%d; ", i, flow_entry->sc->sc[i].destination);
                        }
                        printf("\n");
                }
                printf("\n");
                entry += 1;
        }
}

static int
run_cli(void) {
        printf("Hello from run_cli()\n");
        char *line;
        char **args;
        int status = 1;

        // state_info = rte_calloc("state", 1, sizeof(struct state_info), 0);
        // if (state_info == NULL) {
        //         rte_exit(EXIT_FAILURE, "Unable to initialize NF state");
        // }
        // printf("state_info is not NULL\n");

        do {
          printf("> ");
          line = lsh_read_line();
          args = lsh_split_line(line);
          //status = lsh_execute(args);
          if (args[0] == NULL) {
                  printf("empty command\n");
          } else if (strcmp(args[0], "show") == 0) {
                  show_flow_table();
          } else if (strcmp(args[0], "add") == 0) {
                  add_ft_entry(args);
          } else if (strcmp(args[0], "exit") == 0) {
                  printf("exiting the CLI. Rerun test_flow_dir() to get back to CLI. \n");
                  status = 0;
          } else {
                  printf("invalid command, supported commands are only: show, add, del.\n");
                  cli_help();
          }

          free(line);
          free(args);
        } while (status);

				return 0;
}

int
main(int argc, char *argv[]) {
        int arg_offset;
        struct onvm_nf_local_ctx *nf_local_ctx;
        struct onvm_nf_function_table *nf_function_table;
        const char *progname = argv[0];

        nf_local_ctx = onvm_nflib_init_nf_local_ctx();
        onvm_nflib_start_signal_handler(nf_local_ctx, NULL);

        nf_function_table = onvm_nflib_init_nf_function_table();
        nf_function_table->pkt_handler = &packet_handler;

        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, nf_local_ctx, nf_function_table)) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                if (arg_offset == ONVM_SIGNAL_TERMINATION) {
                        printf("Exiting due to user termination\n");
                        return 0;
                } else {
                        rte_exit(EXIT_FAILURE, "Failed ONVM init\n");
                }
        }

        argc -= arg_offset;
        argv += arg_offset;
        destination = nf_local_ctx->nf->service_id + 1;

        if (parse_app_args(argc, argv, progname) < 0)
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");

        /* Map the sdn_ft table */
        onvm_flow_dir_nf_init();

        printf("--- foo\n");

				// run CLI on a separate process
			  pid_t pid;
  			pid = fork();
  			if (pid == 0) {
    						// Child process
		 				    if (run_cli() == -1) {
		 				      			perror("failed to execute run_cli()");
                        exit(EXIT_FAILURE);
		 				    }
		 				    exit(EXIT_FAILURE);
		 		} else if (pid < 0) {
		 				    // Error forking
		 				    perror("failed to fork a process");
                exit(EXIT_FAILURE);
			  } else {
		 				    // Parent process
                onvm_nflib_run(nf_local_ctx);
                onvm_nflib_stop(nf_local_ctx);
                printf("If we reach here, program is ending\n");
                return 0;

		 				    // do {
					 			// 	      wpid = waitpid(pid, &status, WUNTRACED);
		 				    // } while (!WIFEXITED(status) && !WIFSIGNALED(status));
		 		}

        // onvm_nflib_run(nf_local_ctx);

        // onvm_nflib_stop(nf_local_ctx);
        // printf("If we reach here, program is ending\n");
        // return 0;
}
