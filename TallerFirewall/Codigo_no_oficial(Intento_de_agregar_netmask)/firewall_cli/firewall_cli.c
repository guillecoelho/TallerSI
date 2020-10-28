#include <arpa/inet.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../firewall.h"

#define PORT_NUM_MAX USHRT_MAX

static void print_usage(void) {
    printf(
        "Usage: tsiFirewall ...\n\n"
        "Select one of the 5 modes:\n"
        "-a --add            add a rule\n"
        "-r --remove         remove a rule\n"
        "-g --general        change default policy\n"
        "-v --view           view rules\n"
        "-h --help           help\n\n"

        "For options [add, remove, general] specify the rule: \n"
        "-i --in             input\n"
        "-o --out            output\n"
        "-b --block          block\n"
        "-u --unblock        allow\n\n"
        "-s --s_ip      [IPADDRESS]     source ip address\n"
        "-m --s_mask    [MASK]          source mask (Values from 1 - 32)\n"
        "-p --s_port    [PORT]          source port\n"
        "-d --d_ip      [IPADDRESS]     destination ip address\n"
        "-n --d_mask    [MASK]          destination mask (Values from 1 - 32)\n"
        "-q --d_port    [PORT]          destination port\n"
        "-c --proto     [PROTOCOL]      protocol(%d=ICMP, %d=UDP, %d=TCP)\n"
        "-x --index     [INDEX]         insert new rule before the rule at the given index\n\n"
        "Examples of use:\n"
        "*Add a new rule:\n"
        "   tsiFirewall -a -b -i -s 192.168.1.201 -p 5555 -d 192.168.222.1 -q 2222 -c 17 -x 1\n"
        "*Remove a old rule:\n"
        "   tsiFirewall -r -b -i -s 192.168.1.201 -p 5555 -d 192.168.222.1 -q 2222 -c 17\n"
        "*Change default policy:\n"
        "   tsiFirewall -g -b -i\n",
                IPPROTO_ICMP,IPPROTO_UDP,IPPROTO_TCP
);
}

/*
 * The function sends a command to a MiniFirewall module via a device file.
 */
static void send_instruction(struct fw_ctl *ctl) {
    FILE *fp;
    int byte_count;

    fp = fopen("/proc/tsiFirewall", "w");
    if (fp == NULL) {
        printf("An device file (%s) cannot be opened.\n", DEVICE_INTF_NAME);
        return;
    }
    byte_count = fwrite(ctl, 1, sizeof(*ctl), fp);
    if (byte_count != sizeof(*ctl))
        printf("Write process is incomplete. Please try again.\n");

    fclose(fp);
}

/*
 * The function prints all existing rules, installed in the kernel module.
 */
static void view_rules(void) {
    FILE *fp;
    char *buffer;
    int byte_count;
    struct in_addr addr;
    struct fw_rule *rule;
    unsigned int Out_policy;
    unsigned int In_policy;
    struct fw_ctl *ctl;
    int counter_in_rules = 0;
    int counter_out_rules = 0;

    fp = fopen("/proc/tsiFirewall", "r");
    if (fp == NULL) {
        printf("An device file (%s) cannot be opened.\n", DEVICE_INTF_NAME);
        return;
    }

    buffer = (char *)malloc(sizeof(*ctl));
    if (buffer == NULL) {
        printf("Rule cannot be printed duel to insufficient memory\n");
        return;
    }

    /* Each rule is printed line-by-line. */
	printf("Index   I/O  "
           "S_Addr           S_Mask           S_Port "
	       "D_Addr           D_Mask           D_Port Proto  Action\n");
    while ((byte_count = fread(buffer, 1, sizeof(struct fw_ctl), fp)) > 0) {
        ctl = (struct fw_ctl *)buffer;
        rule = &ctl->rule;
        if (ctl->mode == FW_POLICY) {
            if (rule->in == 1) In_policy = rule->action;
            if (rule->in == 0) Out_policy = rule->action;
        } else if (ctl->mode == FW_VIEW) {
            if (rule->in) {
                counter_in_rules += 1;
                printf("%-5d   ", counter_in_rules);
            } else {
                counter_out_rules += 1;
                printf("%-5d   ", counter_out_rules);
            }
            
            printf("%-3s  ", rule->in ? "In" : "Out");
            addr.s_addr = rule->s_ip;
            printf("%-15s  ", inet_ntoa(addr));
            addr.s_addr = rule->s_mask;
            printf("%-15s  ", inet_ntoa(addr));
            printf("%-5d  ", ntohs(ctl->rule.s_port));
            addr.s_addr = rule->d_ip;
            printf("%-15s  ", inet_ntoa(addr));
            addr.s_addr = rule->d_mask;
            printf("%-15s  ", inet_ntoa(addr));
            printf("%-5d  ", ntohs(rule->d_port));
            printf("%-3d", rule->proto);
            printf("%-5s\n", rule->action ? "    Allow" : "    Deny");
        }
    }
    printf("\n* Default policy for Inbound Packet: %s\n", In_policy ? "Allow" : "Deny");
    printf("* Default policy for Outund Packet: %s\n", Out_policy ? "Allow" : "Deny");
    free(buffer);
    fclose(fp);
}

/*
 * The function parses a string and checks its range.
 */
static int64_t parse_number(const char *str, uint32_t min_val,
                            uint32_t max_val) {
    uint32_t num;
    char *end;

    num = strtol(str, &end, 10);
    if (end == str || (num > max_val) || (num < min_val)) return -1;

    return num;
}

/*
 * The function parses arguments (argv) to form a control instruction.
 */
static int parse_arguments(int argc, char **argv, struct fw_ctl *ret_ctl) {
    int opt;
    int64_t lnum;
    int opt_index;
    struct fw_ctl ctl = {};
    struct in_addr addr;

    /* Long option configuration */
    static struct option long_options[] = {
        {"in", no_argument, 0, 'i'},
        {"out", no_argument, 0, 'o'},
        {"s_ip", required_argument, 0, 's'},
        {"s_mask", required_argument, 0, 'm'},
        {"s_port", required_argument, 0, 'p'},
        {"d_ip", required_argument, 0, 'd'},
        {"d_mask", required_argument, 0, 'n'},
        {"d_port", required_argument, 0, 'q'},
        {"proto", required_argument, 0, 'c'},
        {"add", no_argument, 0, 'a'},
        {"remove", no_argument, 0, 'r'},
        {"view", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"block", no_argument, 0, 'b'},
        {"unblock", no_argument, 0, 'u'},
        {"general", no_argument, 0, 'g'},
        {"index", required_argument, 0, 'x'},
        {0, 0, 0, 0}};

    if (argc == 1) {
        print_usage();
        return 0;
    }

    ctl.mode = FW_NONE;
    ctl.index = 0;
    ctl.rule.in = 255;
    ctl.rule.action = 255;
    while (1) {
        opt_index = 0;
        opt = getopt_long(argc, argv, "ios:m:p:d:n:q:c:x:garvhbu", long_options, &opt_index);
        if (opt == -1) {
            break;
        }

        switch (opt) {
            case 'i': /* Inbound rule */
                if (ctl.rule.in == 0) {
                    printf("Please select either In or Out\n");
                    return -1;
                }
                ctl.rule.in = 1;
                break;
            case 'o': /* Outbound rule */
                if (ctl.rule.in == 1) {
                    printf("Please select either In or Out\n");
                    return -1;
                }
                ctl.rule.in = 0;
                break;
            case 'b': /* Block package */
                if (ctl.rule.action == 1) {
                    printf("Please select either block or unblock\n");
                    return -1;
                }
                ctl.rule.action = 0;
                break;
            case 'u': /* Allow package */
                if (ctl.rule.action == 0) {
                    printf("Please select either block or unblock\n");
                    return -1;
                }
                ctl.rule.action = 1;
                break;
            case 's': /* Source ip address */
                if (inet_aton(optarg, &addr) == 0) {
                    printf("Invalid source ip address\n");
                    return -1;
                }
                ctl.rule.s_ip = addr.s_addr;
                break;
            case 'm': /* Source subnet mask */
                lnum = parse_number(optarg, 0, USHRT_MAX);
                if (lnum < 0 || lnum > 32) {
                    printf("Invalid source subnet mask\n");
                    return -1;
                }
                ctl.rule.s_mask = lnum;
                break;
            case 'p': /* Source port number */
                lnum = parse_number(optarg, 0, USHRT_MAX);
                if (lnum < 0) {
                    printf("Invalid source port number\n");
                    return -1;
                }
                ctl.rule.s_port = htons((uint16_t)lnum);
                break;
            case 'd': /* Destination ip address */
                if (inet_aton(optarg, &addr) == 0) {
                    printf("Invalid destination ip address\n");
                    return -1;
                }
                ctl.rule.d_ip = addr.s_addr;
                break;
            case 'n': /* Destination subnet mask */
                lnum = parse_number(optarg, 0, USHRT_MAX);
                if (lnum < 0 || lnum > 32) {
                    printf("Invalid dest subnet mask\n");
                    return -1;
                }
                ctl.rule.d_mask = lnum;
                break;
            case 'q': /* Destination port number */
                lnum = parse_number(optarg, 0, USHRT_MAX);
                if (lnum < 0) {
                    printf("Invalid destination port number\n");
                    return -1;
                }
                ctl.rule.d_port = htons((uint16_t)lnum);
                break;
            case 'c': /* Protocol number */
                lnum = parse_number(optarg, 0, UCHAR_MAX);
                if (lnum < 0 || !(lnum == 0 || lnum == IPPROTO_TCP ||
                                  lnum == IPPROTO_UDP)) {
                    printf("Invalid protocol number\n");
                    return -1;
                }
                ctl.rule.proto = (uint8_t)lnum;
                break;
            case 'a': /* Add rule */
                if (ctl.mode != FW_NONE) {
                    printf("Only one mode can be selected.\n");
                    return -1;
                }
                ctl.mode = FW_ADD;
                break;
            case 'r': /* Remove rule */
                if (ctl.mode != FW_NONE) {
                    printf("Only one mode can be selected.\n");
                    return -1;
                }
                ctl.mode = FW_REMOVE;
                break;
            case 'v': /* View rules */
                if (ctl.mode != FW_NONE) {
                    printf("Only one mode can be selected.\n");
                    return -1;
                }
                ctl.mode = FW_VIEW;
                break;
            case 'g': /* Change policy rules */
                if (ctl.mode != FW_NONE) {
                    printf("Only one mode can be selected.\n");
                    return -1;
                }
                ctl.mode = FW_POLICY;
                break;
            case 'x': /* Index number */
                lnum = parse_number(optarg, 0, UCHAR_MAX);
                if (lnum <= 0) {
                    printf("Invalid index number\n");
                    return -1;
                }
                ctl.index = (uint8_t)lnum;
                break;
            case 'h':
            case '?':
            default:
                print_usage();
                return -1;
        }
    }
    if (ctl.mode == FW_NONE) {
        printf("Please specify mode --(add|remove|view|policy)\n");
        return -1;
    }
    if (ctl.mode != FW_VIEW && ctl.rule.in == 255) {
        printf("Please specify either In or Out\n");
        return -1;
    }

    if (ctl.mode != FW_VIEW && ctl.rule.action == 255) {
        printf("Please specify either block or unblock\n");
        return -1;
    }

    *ret_ctl = ctl;
    return 0;
}

int main(int argc, char *argv[]) {
    struct fw_ctl ctl = {};
    int ret;

    ret = parse_arguments(argc, argv, &ctl);
    if (ret < 0) return ret;

    switch (ctl.mode) {
        case FW_ADD:
            send_instruction(&ctl);
            break;
        case FW_REMOVE:
            send_instruction(&ctl);
            break;
        case FW_POLICY:
            send_instruction(&ctl);
            break;
        case FW_VIEW:
            view_rules();
            break;
        default:
            return 0;
    }
}
