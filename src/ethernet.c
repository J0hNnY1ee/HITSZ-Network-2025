#include "ethernet.h"
#include "arp.h"
#include "driver.h"
#include "ip.h"
#include "net.h"
#include "utils.h"
/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf) {
    // Step 1: 数据长度检查
    if (buf->len < sizeof(ether_hdr_t)) {
        // 数据长度小于以太网头部长度，丢弃数据包
        return;
    }

    // 获取以太网头部指针
    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;

    // Step 2: 移除以太网包头
    if (buf_remove_header(buf, sizeof(ether_hdr_t)) != 0) {
        // 如果移除头部失败，直接返回
        return;
    }

    // Step 3: 向上层传递数据包
    // 提取协议类型字段并转换为主机字节序
    uint16_t protocol = swap16(hdr->protocol16);

    // 调用 net_in 函数向上层传递数据包
    net_in(buf, protocol, hdr->src);
}
/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol) {
   // Step 1: 检查数据包长度是否小于以太网最小传输单元
    if (buf->len < ETHERNET_MIN_TRANSPORT_UNIT) {
        size_t padding_len = ETHERNET_MIN_TRANSPORT_UNIT - buf->len;

        if (buf_add_padding(buf, padding_len) != 0) {
            return;
        }
    }

    // Step 2: 添加以太网头部
    if (buf_add_header(buf, sizeof(ether_hdr_t)) != 0) {
        return;
    }

    ether_hdr_t *hdr = (ether_hdr_t *)buf->data;

    // Step 3: 填写目的 MAC 地址
    memcpy(hdr->dst, mac, NET_MAC_LEN);

    // Step 4: 填写源 MAC 地址
    memcpy(hdr->src, net_if_mac, NET_MAC_LEN);

    // Step 5: 填写协议类型
    hdr->protocol16 = swap16((uint16_t)protocol); 
    // Step 6: 发送数据帧
    if (driver_send(buf) != 0) {
        return;
    }
}
/**
 * @brief 初始化以太网协议
 *
 */
void ethernet_init() {
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 *
 */
void ethernet_poll() {
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}