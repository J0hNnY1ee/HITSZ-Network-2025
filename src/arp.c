

/*ARP 协议以目标 IP 地址为线索，
用于定位下一个应该接收数据包的网
络设备对应的 MAC 地址。若目标主机
不在同一链路上，可通过 ARP 查找下一跳网关的 MAC 地址。*/
#include "arp.h"

#include "ethernet.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
/**
 * @brief 初始的arp包
 *
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = swap16(ARP_HW_ETHER),
    .pro_type16 = swap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 *
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 *
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 *
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp) {
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 *
 */
void arp_print() {
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 *
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip) {
    void *cached_mac = map_get(&arp_table, target_ip);
    if (cached_mac) {
        printf("ARP cache hit for IP: %s\n", iptos(target_ip));
        return;  // 如果缓存命中，直接返回，无需发送 ARP 请求
    }
    // Step1. 初始化缓冲区：
    buf_init(&txbuf, sizeof(arp_pkt_t));
    // Step2. 填写ARP报头:
    arp_pkt_t arp_pkt = arp_init_pkt;
    memcpy(arp_pkt.target_ip, target_ip, NET_IP_LEN);
    memcpy(arp_pkt.target_mac, ether_broadcast_mac, NET_MAC_LEN);

    // Step3. 设置操作类型：
    arp_pkt.opcode16 = swap16(ARP_REQUEST);
    // Step4. 发送 ARP 报文：
    ethernet_out(&txbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);

    printf("Sent ARP request for IP: %s\n", iptos(target_ip));
}

/**
 * @brief 发送一个arp响应
 *
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac) {
    // Step1. 初始化缓冲区：
    buf_init(&txbuf, sizeof(arp_pkt_t));
    // Step2. 填写 ARP 报头首部：
    arp_pkt_t arp_pkt = arp_init_pkt;
    arp_pkt.opcode16 = swap16(ARP_REPLY);
    arp_pkt.hw_type16 = swap16(ARP_HW_ETHER);
    arp_pkt.pro_type16 = swap16(NET_PROTOCOL_IP);
    arp_pkt.hw_len = NET_MAC_LEN;
    arp_pkt.pro_len = NET_IP_LEN;
    memcpy(arp_pkt.sender_ip, net_if_ip, NET_IP_LEN);
    memcpy(arp_pkt.sender_mac, net_if_mac, NET_MAC_LEN);
    memcpy(arp_pkt.target_ip, target_ip, NET_IP_LEN);
    memcpy(arp_pkt.target_mac, target_mac, NET_MAC_LEN);


    memcpy(txbuf.data, &arp_pkt, sizeof(arp_pkt));
    // Step3. 发送 ARP 报文：
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac) {
    // Step1. 检查数据长度：
    if (buf->len < sizeof(arp_pkt_t)) {
        printf("Invalid ARP packet length. Dropping packet.\n");
        return;  // 数据包不完整，丢弃
    }
    // Step2. 报头检查：
    //  检查硬件类型是否为以太网
    arp_pkt_t *arp_pkt = (arp_pkt_t *)buf->data;
    if (swap16(arp_pkt->hw_type16) != ARP_HW_ETHER) {
        printf("Unsupported hardware type in ARP packet. Dropping packet.\n");
        return;
    }

    // 检查协议类型是否为 IPv4
    if (swap16(arp_pkt->pro_type16) != NET_PROTOCOL_IP) {
        printf("Unsupported protocol type in ARP packet. Dropping packet.\n");
        return;
    }

    // 检查 MAC 地址长度是否正确
    if (arp_pkt->hw_len != NET_MAC_LEN) {
        printf("Invalid MAC address length in ARP packet. Dropping packet.\n");
        return;
    }

    // 检查 IP 地址长度是否正确
    if (arp_pkt->pro_len != NET_IP_LEN) {
        printf("Invalid IP address length in ARP packet. Dropping packet.\n");
        return;
    }

    // 检查操作类型是否为 ARP_REQUEST 或 ARP_REPLY
    uint16_t opcode = swap16(arp_pkt->opcode16);
    if (opcode != ARP_REQUEST && opcode != ARP_REPLY) {
        printf("Unsupported ARP operation type. Dropping packet.\n");
        return;
    }

    // Step3. 更新 ARP 表项：
    map_set(&arp_table, arp_pkt->sender_ip, src_mac);

    // 打印更新信息
    printf("Updated ARP table: IP %s -> MAC %s\n", iptos(arp_pkt->sender_ip), mactos(src_mac));

    // Step 4: 查看缓存情况
    void *cached_buf = map_get(&arp_buf, arp_pkt->sender_ip);
    if (cached_buf) {
        // 有缓存：说明之前发送了 ARP 请求，现在收到了响应
        printf("Found cached packet for IP: %s. Sending it now.\n", iptos(arp_pkt->sender_ip));

        // 将缓存的数据包发送给以太网层
        ethernet_out((buf_t *)cached_buf, arp_pkt->sender_mac, NET_PROTOCOL_IP);

        // 删除缓存的数据包
        map_delete(&arp_buf, arp_pkt->sender_ip);
    } else {
        // 无缓存：检查是否为 ARP 请求报文，且目标 IP 是本机 IP
        if (opcode == ARP_REQUEST && memcmp(arp_pkt->target_ip, net_if_ip, NET_IP_LEN) == 0) {
            printf("Received ARP request for our IP. Sending ARP reply.\n");

            // 发送 ARP 响应
            arp_resp(arp_pkt->sender_ip, arp_pkt->sender_mac);
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip) {
    // TO-DO
    // Step1. 查找 ARP 表：
    void *mac = map_get(&arp_table, ip);
    if (mac) {
        // Step 2: 找到对应 MAC 地址
        printf("Found MAC address for IP: %s in ARP table.\n", iptos(ip));

        // 调用以太网层发送数据包
        ethernet_out(buf, mac, NET_PROTOCOL_IP);
    } else {
        // Step 3: 未找到对应 MAC 地址
        printf("MAC address for IP: %s not found in ARP table.\n", iptos(ip));

        // 检查 arp_buf 中是否已经有缓存的包
        if (map_get(&arp_buf, ip)) {
            // 如果已经存在缓存的包，说明正在等待 ARP 响应，不再发送新的 ARP 请求
            printf("Already waiting for ARP reply for IP: %s. Dropping packet.\n", iptos(ip));
            return;
        }

        // 将当前数据包缓存到 arp_buf 中
        map_set(&arp_buf, ip, buf);

        // 发送 ARP 请求以获取目标 IP 的 MAC 地址
        arp_req(ip);
    }
}

/**
 * @brief 初始化arp协议
 *
 */
void arp_init() {
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, NULL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}