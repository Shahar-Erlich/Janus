#include "Core.hpp"

static struct mnl_socket *nl;
static std::vector<uint32_t> blacklist;

uint32_t to_ipv4(const std::string &ip_str)
{
    uint32_t out;
    if (inet_pton(AF_INET, ip_str.c_str(), &out) != 1)
        throw std::runtime_error("Invalid IP address: " + ip_str);

    return out; // already in network byte order
}

static void nfq_send_verdict(int queue_num, uint32_t id, uint32_t src)
{
    std::unique_ptr<char[]> buf(new char[MNL_SOCKET_BUFFER_SIZE]);
    struct nlmsghdr *nlh;
    struct nlattr *nest;

    nlh = nfq_nlmsg_put(buf.get(), NFQNL_MSG_VERDICT, queue_num);

    if (std::find(blacklist.begin(), blacklist.end(), src) != blacklist.end()) // check if ip is in the list
    {
        nfq_nlmsg_verdict_put(nlh, id, NF_DROP);
        std::cout << "IP " << src << " is blacklisted! dropping packet" << std::endl;
    }
    else
    {
        nfq_nlmsg_verdict_put(nlh, id, NF_ACCEPT);
        std::cout << "Packet Accepted" << std::endl;
    }

    /* example to set the connmark. First, start NFQA_CT section: */
    nest = mnl_attr_nest_start(nlh, NFQA_CT);

    /* then, add the connmark attribute: */
    mnl_attr_put_u32(nlh, CTA_MARK, htonl(42));
    /* more conntrack attributes, e.g. CTA_LABELS could be set here */

    /* end conntrack section */
    mnl_attr_nest_end(nlh, nest);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
    {
        perror("mnl_socket_send");
        exit(EXIT_FAILURE);
    }
}

static int queue_cb(const struct nlmsghdr *nlh, void *data)
{
    struct nfqnl_msg_packet_hdr *ph = NULL;
    struct nlattr *attr[NFQA_MAX + 1] = {};
    uint32_t id = 0, skbinfo;
    struct nfgenmsg *nfg;
    uint16_t plen;
    std::cout << "Got message!" << std::endl;

    if (nfq_nlmsg_parse(nlh, attr) < 0)
    {
        perror("problems parsing");
        return MNL_CB_ERROR;
    }

    nfg = (nfgenmsg *)mnl_nlmsg_get_payload(nlh);

    // attr[] is an array where each index is an NFQUEUE attribute:
    //  Attribute	        Meaning
    //  NFQA_PACKET_HDR	    basic metadata about the packet (id, hook, protocol)
    //  NFQA_PAYLOAD	    the actual packet bytes
    //  NFQA_SKB_INFO	    flags like GRO/GSO/checksum-not-ready
    //  NFQA_CAP_LEN	    original size before truncation
    /* ^ to remember what every index means */
    if (attr[NFQA_PACKET_HDR] == NULL)
    {
        std::cout << "metaheader not set\n"
                  << stderr;
        nfq_send_verdict(ntohs(nfg->res_id), id, 0); // ALWAYS return verdict!
        return MNL_CB_OK;
    }

    ph = (nfqnl_msg_packet_hdr *)mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);

    plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
    void *payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);
    unsigned char *packet = static_cast<unsigned char *>(payload);
    struct iphdr *ip = reinterpret_cast<struct iphdr *>(packet);

    skbinfo = attr[NFQA_SKB_INFO] ? ntohl(mnl_attr_get_u32(attr[NFQA_SKB_INFO])) : 0;

    if (attr[NFQA_CAP_LEN])
    {
        uint32_t orig_len = ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN]));
        if (orig_len != plen)
            std::cout << "truncated ";
    }

    if (skbinfo & NFQA_SKB_GSO)
        std::cout << "GSO ";

    id = ntohl(ph->packet_id);
    std::cout << "packet received (id=" << id << ", hw = " << ntohs(ph->hw_protocol) << ", hook = " << ph->hook << ", payload len = " << plen << std::endl;

    /*
     * ip/tcp checksums are not yet valid, e.g. due to GRO/GSO.
     * The application should behave as if the checksums are correct.
     *
     * If these packets are later forwarded/sent out, the checksums will
     * be corrected by kernel/hardware.
     */
    if (skbinfo & NFQA_SKB_CSUMNOTREADY)
        std::cout << ", checksum not ready";
    std::cout << ")";

    nfq_send_verdict(ntohs(nfg->res_id), id, ip->saddr);

    return MNL_CB_OK;
}

int main(int argc, char *argv[])
{
    blacklist.push_back(to_ipv4("192.168.0.2"));

    /* largest possible packet payload, plus netlink data overhead: */
    size_t sizeof_buf = 0xffff + (MNL_SOCKET_BUFFER_SIZE / 2);
    std::unique_ptr<char[]> buf(new char[sizeof_buf]);

    struct nlmsghdr *nlh;
    int ret;
    unsigned int portid, queue_num;
    queue_num = 0;

    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == NULL)
    {
        perror("mnl_socket_open");
        exit(EXIT_FAILURE);
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
    {
        perror("mnl_socket_bind");
        exit(EXIT_FAILURE);
    }
    portid = mnl_socket_get_portid(nl);

    if (!buf)
    {
        perror("allocate receive buffer");
        exit(EXIT_FAILURE);
    }

    nlh = nfq_nlmsg_put(buf.get(), NFQNL_MSG_CONFIG, queue_num);
    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
    {
        perror("mnl_socket_send");
        exit(EXIT_FAILURE);
    }

    nlh = nfq_nlmsg_put(buf.get(), NFQNL_MSG_CONFIG, queue_num);
    nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
    mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
    {
        perror("mnl_socket_send");
        exit(EXIT_FAILURE);
    }

    /* ENOBUFS is signalled to userspace when packets were lost
     * on kernel side.  In most cases, userspace isn't interested
     * in this information, so turn it off.
     */
    ret = 1;
    mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &ret, sizeof(int));

    for (;;)
    {
        int ret = mnl_socket_recvfrom(nl, buf.get(), sizeof_buf);
        if (ret == -1)
        {
            perror("mnl_socket_recvfrom");
            continue;
        }

        ret = mnl_cb_run(buf.get(), ret, 0, mnl_socket_get_portid(nl), queue_cb, NULL);
        if (ret <= 0)
        {
            // ZERO means “continue”, negative means “stop”, both are fine
            continue;
        }
    }

    mnl_socket_close(nl);

    return 0;
}