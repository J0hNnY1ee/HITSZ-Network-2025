#include "icmp.h"

#include "ip.h"
#include "net.h"

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
    // Step1: 初始化 txbuf 并封装 ICMP 数据
    buf_init(&txbuf, req_buf->len);
    
    // 获取 ICMP 请求头部指针
    icmp_hdr_t *req_hdr = (icmp_hdr_t *)req_buf->data;
    
    // 构造 ICMP 响应头部
    icmp_hdr_t *resp_hdr = (icmp_hdr_t *)txbuf.data;
    resp_hdr->type = ICMP_TYPE_ECHO_REPLY;   // 设置为回显应答
    resp_hdr->code = 0;                      // code 字段为 0
    resp_hdr->id16 = req_hdr->id16;          // 复制标识符
    resp_hdr->seq16 = req_hdr->seq16;        // 复制序号

    // 拷贝请求数据部分到响应中（不包括 ICMP header）
    memcpy(txbuf.data + sizeof(icmp_hdr_t),
           req_buf->data + sizeof(icmp_hdr_t),
           req_buf->len - sizeof(icmp_hdr_t));

    // Step2: 计算校验和（注意校验和字段本身设为0再计算）
    resp_hdr->checksum16 = 0;
    resp_hdr->checksum16 = checksum16((uint16_t *)resp_hdr, txbuf.len);

    // Step3: 调用 ip_out 发送 ICMP 响应
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

#define ICMP_HDR_SIZE sizeof(icmp_hdr_t)
/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    // Step1: 检查数据包长度是否足够容纳 ICMP 报头
    if (buf->len < ICMP_HDR_SIZE) {
        // 包太短，不合法，丢弃
        return;
    }

    // 获取 ICMP 报头指针
    icmp_hdr_t *hdr = (icmp_hdr_t *)buf->data;

    // Step2: 查看 ICMP 类型
    if (hdr->type == ICMP_TYPE_ECHO_REQUEST) {
        // Step3: 是回显请求，发送回显应答
        icmp_resp(buf, src_ip);
    }
}

#define ICMP_HDR_SIZE sizeof(icmp_hdr_t)
#define IP_HDR_SIZE sizeof(ip_hdr_t)
#define ICMP_UNREACH_DATA_LEN (IP_HDR_SIZE + 8) // ICMP 不可达报文数据长度

/**
 * @brief 发送 ICMP 不可达差错报文
 *
 * @param recv_buf 收到的无法处理的 IP 数据包
 * @param src_ip 目标主机的源 IP 地址（即差错发生处）
 * @param code 差错码（协议不可达或端口不可达）
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    // Step1: 初始化 txbuf 并填写 ICMP 报头
    size_t total_len = ICMP_HDR_SIZE + ICMP_UNREACH_DATA_LEN;
    buf_init(&txbuf, total_len);

    icmp_hdr_t *hdr = (icmp_hdr_t *)txbuf.data;
    hdr->type = ICMP_TYPE_UNREACH;       // 类型：目的不可达
    hdr->code = code;                    // 差错码（协议/端口不可达）
    hdr->id16 = 0;                       // 未使用，置零
    hdr->seq16 = 0;                      // 未使用，置零

    // Step2: 填充 ICMP 数据部分：IP 首部 + 前 8 字节数据
    uint8_t *data = txbuf.data + ICMP_HDR_SIZE;

    // 拷贝收到的 IP 首部
    ip_hdr_t *ip_hdr = (ip_hdr_t *)recv_buf->data;
    memcpy(data, ip_hdr, IP_HDR_SIZE);

    // 拷贝收到的 IP 数据前 8 字节（注意不要越界）
    size_t data_to_copy = (recv_buf->len - (recv_buf->data - recv_buf->payload)) > 8 ?
                          8 : (recv_buf->len - (recv_buf->data - recv_buf->payload));
    memcpy(data + IP_HDR_SIZE, recv_buf->data, data_to_copy);

    // 填写校验和
    hdr->checksum16 = 0;
    hdr->checksum16 = checksum16((uint16_t *)hdr, txbuf.len);

    // Step3: 调用 ip_out 发送 ICMP 不可达报文
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}