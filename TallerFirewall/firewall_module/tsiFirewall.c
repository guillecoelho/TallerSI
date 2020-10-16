#include <linux/fs.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netfilter_ipv4.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/inet.h>
#include "../firewall.h"

#define EQUAL_NET_ADDR(ip1, ip2) ((ip1 ^ ip2) == 0)
#define EQUAL_NET_ADDR_MASK(ip1, ip2, mask) (((ip1 ^ ip2) & mask) == 0)
#define NOT_ZERO(x) (x != 0)
#define IP_POS(ip, i) (ip >> ((8 * (3 - i))) & 0xFF)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sucha Supittayapornpong <sucha.cpe@gmail.com>");

/* List node containing a filter rule */
struct rule_node {
    struct mfw_rule rule;
    struct list_head list;
};

struct list_head In_lhead;       /* Head of inbound-rule list */
static unsigned char In_policy;  /* Default policy for inbound list*/
struct list_head Out_lhead;      /* Head of outbound-rule list */
static unsigned char Out_policy; /* Default policy for inbound list*/

static int Device_open; /* Opening counter of a device file */
static char *Buffer;    /* A buffer for receving data from a user space */

static bool check_ip(unsigned int ip, unsigned int rule_ip,
                     unsigned int rule_mask) {
    bool a = false;
    /*if (NOT_ZERO(rule_mask)) {
        printk(KERN_INFO "Check ip with mask");
        printk(KERN_INFO "IP: %d", rule_mask);
        a = EQUAL_NET_ADDR_MASK(ip, rule_ip, rule_mask);
    } else {*/
        printk(KERN_INFO "IP: %d", ip);
        printk(KERN_INFO "RULE IP: %d", rule_ip);
        a =  EQUAL_NET_ADDR(ip, rule_ip);
    //}
    printk(KERN_INFO "Check ip result %d",a);
    return a;
}

/*
 * General filter uses exact match algorithm based on the given rule list.
 */
unsigned int mfw_general_filter(void *priv, struct sk_buff *skb,
                                       const struct nf_hook_state *state,
                                       struct list_head *rule_list_head,
                                       unsigned char policy) {
    struct list_head *listh;
    struct rule_node *node;
    struct mfw_rule *r;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;

    uint32_t s_ip;
    uint32_t d_ip;
    uint16_t s_port;
    uint16_t d_port;
    unsigned char proto;

    if (!skb || rule_list_head->next == rule_list_head)
        return NF_ACCEPT;

    /* Get IP header and extract information */
    iph = (struct iphdr *)skb_network_header(skb);
    if (iph == NULL) return NF_ACCEPT;
    
    proto = iph->protocol;
    s_ip = iph->saddr;
    d_ip = iph->daddr;
    if (proto == IPPROTO_UDP) {
        udph = (struct udphdr *)(skb_transport_header(skb));
        s_port = udph->source;
        d_port = udph->dest;
    } else if (proto == IPPROTO_TCP) {
        tcph = (struct tcphdr *)(skb_transport_header(skb));
        s_port = tcph->source;
        d_port = tcph->dest;
    } else if (proto == IPPROTO_ICMP) {
        printk(KERN_INFO "Dont skip protocol: ICMP PACJAGE,");
    } else
        return NF_ACCEPT;
    
    /* Loop through the rule list and perform exact match */
    listh = rule_list_head;
    list_for_each_entry(node, listh, list) {
        r = &node->rule;

        if (NOT_ZERO(r->proto) && (r->proto != iph->protocol)) continue;
        if (NOT_ZERO(r->s_ip) && !check_ip(s_ip, r->s_ip, r->s_mask)) continue;
        if (proto != IPPROTO_ICMP) {
            if (NOT_ZERO(r->s_port) && (r->s_port != s_port)) continue;
        }
        if (NOT_ZERO(r->d_ip) && !check_ip(d_ip, r->d_ip, r->d_mask)) continue;
        if (proto != IPPROTO_ICMP) {
            if (NOT_ZERO(r->d_port) && (r->d_port != d_port)) continue;
        }
        if (r->action == 1){
            return NF_ACCEPT;
       } else if (r->action == 0) {
            printk(KERN_INFO
                   "MiniFirewall: Drop packet "
                   "src %d.%d.%d.%d : %d   dst %d.%d.%d.%d : %d   proto %d\n",
                   IP_POS(s_ip, 3), IP_POS(s_ip, 2), IP_POS(s_ip, 1),
                   IP_POS(s_ip, 0), s_port, IP_POS(d_ip, 3), IP_POS(d_ip, 2),
                   IP_POS(d_ip, 1), IP_POS(d_ip, 0), d_port, iph->protocol);
            return NF_DROP;
        }
    }
    //return NF_ACCEPT;
    /* No rule match, apply default policy */
    return (policy == 0 ? NF_DROP : NF_ACCEPT);
}

/*
 * Inbound filter is applied to all inbound packets.
 */
unsigned int mfw_in_filter(void *priv, struct sk_buff *skb,
                                  const struct nf_hook_state *state) {
    return mfw_general_filter(priv, skb, state, &In_lhead, In_policy);
}

/*
 * Outbound filter is applied to all outbound packets.
 */
unsigned int mfw_out_filter(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state) {
    return mfw_general_filter(priv, skb, state, &Out_lhead, Out_policy);
}

/*
 * The function handles an open operation of a device file.
 */
int mfw_dev_open(struct inode *inode, struct file *file) {
    if (Device_open) return -EBUSY;

    /* Increase value to enforce a signal access policy */
    Device_open++;

    if (!try_module_get(THIS_MODULE)) {
        printk(KERN_ALERT "MiniFirewall: Module is not available\n");
        return -ESRCH;
    }
    return 0;
}

/*
 * The function handles a release operation of a device file.
 */
int mfw_dev_release(struct inode *inode, struct file *file) {
    module_put(THIS_MODULE);
    Device_open--;
    return 0;
}

/*
 * The function handles user-space view operation, which reads inbound and
 * outbound rules stored in the module. The function is called iteratively
 * until it returns 0.
 */
ssize_t mfw_dev_read(struct file *file, char *buffer, size_t length,
                            loff_t *offset) {
    int byte_read = 0;
    static struct list_head *inlp = &In_lhead;
    static struct list_head *outlp = &Out_lhead;
    struct rule_node *node;
    char *readptr;
    
    printk(KERN_ALERT "leyendo regla");
    /* Read a rule if it is not the last one in the inbound list */
    if (inlp->next != &In_lhead) {
        node = list_entry(inlp->next, struct rule_node, list);
        readptr = (char *)&node->rule;
        inlp = inlp->next;
    }
    /* Read a rule if it is not the last one in the outbound list */
    else if (outlp->next != &Out_lhead) {
        node = list_entry(outlp->next, struct rule_node, list);
        readptr = (char *)&node->rule;
        outlp = outlp->next;
    }
    /* Reset reading pointers to heads of inbound and outbound lists */
    else {
        inlp = &In_lhead;
        outlp = &Out_lhead;
        
        return 0;
    }

    /* Write to a user-space buffer */
    while (length && (byte_read < sizeof(struct mfw_rule))) {
        put_user(readptr[byte_read], &(buffer[byte_read]));
        byte_read++;
        length--;
    }
    return byte_read;
}

/*
 * The function adds a rule to either an inbound list or an outbound list.
 */
void mfw_rule_add(struct mfw_rule *rule) {
    struct rule_node *nodep;
    nodep = (struct rule_node *)kmalloc(sizeof(struct rule_node), GFP_KERNEL);
    if (nodep == NULL) {
        printk(KERN_ALERT
               "MiniFirewall: Cannot add a new rule due to "
               "insufficient memory\n");
        return;
    }
    nodep->rule = *rule;

    if (nodep->rule.in == 1) {
        list_add_tail(&nodep->list, &In_lhead);
        printk(KERN_INFO "MiniFirewall: Add rule to the inbound list ");
    } else {
        list_add_tail(&nodep->list, &Out_lhead);
        printk(KERN_INFO "MiniFirewall: Add rule to the outbound list ");
    }
    printk(KERN_INFO "src %d.%d.%d.%d : %d   dst %d.%d.%d.%d : %d   proto %d  <--- %d\n",
           IP_POS(rule->s_ip, 3), IP_POS(rule->s_ip, 2), IP_POS(rule->s_ip, 1),
           IP_POS(rule->s_ip, 0), rule->s_port, IP_POS(rule->d_ip, 3),
           IP_POS(rule->d_ip, 2), IP_POS(rule->d_ip, 1), IP_POS(rule->d_ip, 0),
           rule->d_port, rule->proto, rule->action);
}

/*
 * The function deletes a rule from inbound and outbound lists.
 */
void mfw_rule_del(struct mfw_rule *rule) {
    struct rule_node *node;
    struct list_head *lheadp;
    struct list_head *lp;

    if (rule->in == 1)
        lheadp = &In_lhead;
    else
        lheadp = &Out_lhead;

    for (lp = lheadp; lp->next != lheadp; lp = lp->next) {
        node = list_entry(lp->next, struct rule_node, list);
        if (node->rule.in == rule->in && node->rule.s_ip == rule->s_ip &&
            node->rule.s_mask == rule->s_mask &&
            node->rule.s_port == rule->s_port &&
            node->rule.d_ip == rule->d_ip &&
            node->rule.d_mask == rule->d_mask &&
            node->rule.d_port == rule->d_port &&
            node->rule.proto == rule->proto &&
            node->rule.action == rule->action) {
            list_del(lp->next);
            kfree(node);
            printk(KERN_INFO
                   "MiniFirewall: Remove rule "
                   "src %d.%d.%d.%d : %d   dst %d.%d.%d.%d : %d   "
                   "proto %d\n",
                   IP_POS(rule->s_ip, 3), IP_POS(rule->s_ip, 2),
                   IP_POS(rule->s_ip, 1), IP_POS(rule->s_ip, 0), rule->s_port,
                   IP_POS(rule->d_ip, 3), IP_POS(rule->d_ip, 2),
                   IP_POS(rule->d_ip, 1), IP_POS(rule->d_ip, 0), rule->d_port,
                   rule->proto);
            break;
        }
    }
}

/*
 * The function change de default policy for either an inbound list or an outbound list.
 */
void mfw_rule_policy(struct mfw_rule *rule) {
    struct rule_node *nodep;
    nodep = (struct rule_node *)kmalloc(sizeof(struct rule_node), GFP_KERNEL);
    if (nodep == NULL) {
        printk(KERN_ALERT
               "MiniFirewall: Cannot add a new rule due to "
               "insufficient memory\n");
        return;
    }
    nodep->rule = *rule;

    if (nodep->rule.in == 1) {
        if (nodep->rule.action == 0) {
            In_policy = 0;
        } else if (nodep->rule.action == 1) {
            In_policy = 1;
        }
        printk(KERN_INFO "MiniFirewall: Change default policy to the inbound list");
    } else {
        if (nodep->rule.action == 0) {
            Out_policy = 0;
        } else if (nodep->rule.action == 1) {
            Out_policy = 1;
        }   
        printk(KERN_INFO "MiniFirewall: Change default policy to the outbound list ");
    }
}


/*
 * The function handles user-space write operation, which sends add and remove
 * instruction to the MiniFirewall module
 */
ssize_t mfw_dev_write(struct file *file, const char *buffer,
                             size_t length, loff_t *offset) {
    struct mfw_ctl *ctlp;
    int byte_write = 0;
    printk(KERN_ALERT "MiniFirewall: Try to add rule\n");
    if (length < sizeof(*ctlp)) {
        printk(KERN_ALERT "MiniFirewall: Receives incomplete instruction\n");
        return byte_write;
    }

    /* Transfer user-space data to kernel-space buffer */
    while (length && (byte_write < sizeof(*ctlp))) {
        get_user(Buffer[byte_write], buffer + byte_write);
        byte_write++;
        length--;
    }

    ctlp = (struct mfw_ctl *)Buffer;
    switch (ctlp->mode) {
        case MFW_ADD:
            mfw_rule_add(&ctlp->rule);
            break;
        case MFW_REMOVE:
            mfw_rule_del(&ctlp->rule);
            break;
        case MFW_POLICY:
            mfw_rule_policy(&ctlp->rule);
            break;
        default:
            printk(KERN_ALERT "MiniFirewall: Received an unknown command\n");
    }
    printk(KERN_ALERT "MiniFirewall: Added rule\n");
    return byte_write;
}

/* Inbound hook configuration for netfilter */
struct nf_hook_ops mfw_in_hook_ops = {.hook = mfw_in_filter,
                                      .pf = PF_INET,
                                      .hooknum = NF_INET_LOCAL_IN,
                                      .priority = NF_IP_PRI_FIRST};

/* Outbound hook configuration for netfilter */
struct nf_hook_ops mfw_out_hook_ops = {.hook = mfw_out_filter,
                                       .pf = PF_INET,
                                       .hooknum = NF_INET_LOCAL_OUT,
                                       .priority = NF_IP_PRI_FIRST};

/* File operation configuration for a device file */
struct file_operations mfw_dev_fops = {.owner = THIS_MODULE,
                                       .read = mfw_dev_read,
                                       .write = mfw_dev_write,
                                       .open = mfw_dev_open,
                                       .release = mfw_dev_release};

static struct proc_dir_entry *ent;
/*
 * The MiniFirewall kernel module is initialized by this function.
 */

static int __init mfw_mod_init(void) {
    /* Initialize static global variables */
    Device_open = 0;
    Buffer = (char *)kmalloc(sizeof(struct mfw_ctl *), GFP_KERNEL);
    if (Buffer == NULL) {
        printk(KERN_ALERT
               "MiniFirewall: Fails to start due to out of memory\n");
        return -1;
    }

    INIT_LIST_HEAD(&In_lhead);
    INIT_LIST_HEAD(&Out_lhead);
    In_policy = 0;
    Out_policy = 0;
    /* Register character device */
    // ret = register_chrdev(DEVICE_MAJOR_NUM, DEVICE_INTF_NAME, &mfw_dev_fops);
    ent = proc_create(DEVICE_INTF_NAME, 0660, NULL, &mfw_dev_fops);
    if (ent == NULL) {
        printk(KERN_ALERT "MiniFirewall: Fails to create proc entry\n");
        return -ENOMEM;
    }

    /* Register netfilter inbound and outbound hooks */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    nf_register_net_hook(&init_net, &mfw_in_hook_ops);
    nf_register_net_hook(&init_net, &mfw_out_hook_ops);
#else
    nf_register_hook(&mfw_in_hook_ops);
    nf_register_hook(&mfw_out_hook_ops);
#endif
    printk(KERN_INFO "MiniFirewall loaded!\n");
    return 0;
}

/*
 * The MiniFirewall module is cleaned up by this function.
 */
static void __exit mfw_mod_cleanup(void) {
    struct rule_node *nodep;
    struct rule_node *ntmp;

    kfree(Buffer);

    list_for_each_entry_safe(nodep, ntmp, &In_lhead, list) {
        list_del(&nodep->list);
        kfree(nodep);
        printk(KERN_INFO "MiniFirewall: Deleted inbound rule %p\n", nodep);
    }

    list_for_each_entry_safe(nodep, ntmp, &Out_lhead, list) {
        list_del(&nodep->list);
        kfree(nodep);
        printk(KERN_INFO "MiniFirewall: Deleted outbound rule %p\n", nodep);
    }

    remove_proc_entry(DEVICE_INTF_NAME, NULL);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    nf_unregister_net_hook(&init_net, &mfw_in_hook_ops);
    nf_unregister_net_hook(&init_net, &mfw_out_hook_ops);
#else
    nf_unregister_hook(&mfw_in_hook_ops);
    nf_unregister_hook(&mfw_out_hook_ops);
#endif
}

/* Add the (above) initialize function to the module */
module_init(mfw_mod_init);
/* Add the (above) cleanup function to the module */
module_exit(mfw_mod_cleanup);
