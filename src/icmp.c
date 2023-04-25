#include "buf.h"
#include "net.h"
#include "icmp.h"
#include "ip.h"
#include "utils.h"
#include <string.h>

/**
 * @brief 发送icmp响应
 * 
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip)
{
    // TO-DO
    icmp_hdr_t *req_hdr = req_buf->data;
    buf_init(&txbuf, req_buf->len);
    icmp_hdr_t *hdr = txbuf.data;
    hdr->type = ICMP_TYPE_ECHO_REPLY;
    hdr->code = 0;
    hdr->id16 = req_hdr->id16;
    hdr->seq16 = req_hdr->seq16;
    memcpy(txbuf.data + sizeof(icmp_hdr_t), req_buf->data + sizeof(icmp_hdr_t),
           req_buf->len - sizeof(icmp_hdr_t));
    hdr->checksum16 = 0;
    hdr->checksum16 = checksum16(hdr, txbuf.len);
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    // TO-DO
    if(buf->len < sizeof(icmp_hdr_t))
        return;
    icmp_hdr_t *hdr = buf->data;
    if(hdr->type == ICMP_TYPE_ECHO_REQUEST){
        icmp_resp(buf, src_ip);
    }
}

/**
 * @brief 发送icmp不可达
 * 
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code)
{
    // TO-DO
    buf_init(&txbuf, sizeof(icmp_hdr_t) + 28);
    icmp_hdr_t *hdr = txbuf.data;
    hdr->code = code;
    hdr->type = ICMP_TYPE_UNREACH;
    hdr->id16 = 0;
    hdr->seq16 = 0;
    memcpy(txbuf.data + sizeof(icmp_hdr_t), recv_buf->data - 20, 28);
    hdr->checksum16 = 0;
    hdr->checksum16 = checksum16(hdr, 36);
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 * 
 */
void icmp_init(){
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}